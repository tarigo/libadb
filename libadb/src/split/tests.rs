//! Tests of the split halves, with the send queue, device-initiated
//! channels and back-pressure each in a module of its own.

use super::*;
use crate::base::channel::ChannelId;
use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
use crate::base::ids::{ChannelIds, LocalId, RemoteId};
use crate::base::mock::{
    abandon, now, okay, split_with_channel, withdraw, wrte, Mock, NoAuth, SharedMock,
};
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::slot::{AckDecision, ChannelFault};
use crate::error::Error;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};
use embedded_io::ErrorKind;

/// Stage one OPEN out of the queue, then deliver more packets —
/// the device-side traffic a staged request can race against.
fn staged_with_followup(
    followup: &[Packet],
) -> (
    Reader<SharedMock, SharedMock>,
    SplitIncoming<SharedMock>,
    SharedMock,
) {
    use core::future::Future as _;
    use core::task::{Context, Poll, Waker};

    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    seen.parks_when_drained();

    seen.feed(&Packet::new(Command::Open, 80, 0, b"tcp:80\0".to_vec()));
    let pump = |reader: &mut Reader<SharedMock, SharedMock>| {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        // Everything fed so far is dispatched on the way; the
        // drained mock then parks the read, which is how the pump
        // knows it went all the way through.
        match fut.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            other => panic!("expected the read to wait for more, got {other:?}"),
        }
    };
    pump(&mut reader);
    let inc = reader.try_accept_incoming().expect("the OPEN was queued");

    for pkt in followup {
        seen.feed(pkt);
    }
    pump(&mut reader);
    (reader, inc, seen)
}

#[test]
fn a_device_cancel_reaches_the_staged_request() {
    let (mut reader, inc, seen) = staged_with_followup(&[withdraw(80)]);

    // The verdict observes the withdrawal: no READY, no channel.
    let err = now(inc.accept()).unwrap_err();
    assert!(
        matches!(err, Error::ChannelClosed),
        "expected ChannelClosed, got {err:?}"
    );
    assert!(
        !seen
            .sent()
            .iter()
            .any(|(cmd, _, arg1, _)| *cmd == Command::Ready && *arg1 == 80),
        "READY must not answer a withdrawn OPEN"
    );
    // The dead request does not come back to the queue either.
    assert!(reader.try_accept_incoming().is_none());
}

#[test]
fn a_staged_reject_after_the_cancel_stays_silent() {
    let (_reader, inc, seen) = staged_with_followup(&[withdraw(80)]);

    now(inc.reject()).unwrap();
    assert!(
        !seen
            .sent()
            .iter()
            .any(|(cmd, _, arg1, _)| *cmd == Command::Close && *arg1 == 80),
        "a withdrawn OPEN expects no answer"
    );
}

#[test]
fn a_withdrawal_racing_the_accept_closes_the_split_slot() {
    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn());
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();

    seen.feed(&Packet::new(Command::Open, 90, 0, b"tcp:90\0".to_vec()));
    let inc = now(reader.accept_incoming()).unwrap();
    let ch = now(inc.accept()).unwrap();

    // The withdrawal crossed our READY: a reader parked on the
    // channel must observe the close, not wait forever.
    seen.feed(&withdraw(90));
    let mut buf = [0u8; 8];
    let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
    assert!(
        matches!(err, Error::ChannelClosed),
        "expected ChannelClosed, got {err:?}"
    );
}

#[test]
fn held_holders_spend_the_open_storm_budget() {
    use core::future::Future as _;
    use core::task::{Context, Poll, Waker};

    let open_pkt =
        |remote_id: u32, dest: &[u8]| Packet::new(Command::Open, remote_id, 0, dest.to_vec());

    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new().with_max_channels(2),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    seen.parks_when_drained();

    let pump = |reader: &mut Reader<SharedMock, SharedMock>| {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            other => panic!("expected the read to wait for more, got {other:?}"),
        }
    };

    // Two held holders exhaust the two-channel budget without ever
    // touching the queue length.
    seen.feed(&open_pkt(60, b"tcp:60\0"));
    pump(&mut reader);
    let held_a = reader.try_accept_incoming().unwrap();
    seen.feed(&open_pkt(61, b"tcp:61\0"));
    pump(&mut reader);
    let held_b = reader.try_accept_incoming().unwrap();
    assert_eq!(reader.shared.lock_incoming().len(), 0);

    // The third OPEN must be refused on arrival: an application
    // sitting on holders cannot make the bound unenforceable.
    seen.feed(&open_pkt(62, b"tcp:62\0"));
    pump(&mut reader);
    assert!(
        seen.sent()
            .iter()
            .any(|(cmd, _, arg1, _)| *cmd == Command::Close && *arg1 == 62),
        "the OPEN past the budget must be refused with CLSE"
    );
    assert!(
        reader.try_accept_incoming().is_none(),
        "nothing may be queued past the budget"
    );

    // The budget comes back with the holders.
    drop(held_a);
    drop(held_b);
    assert_eq!(reader.shared.lock_incoming().len(), 2);
}

#[test]
fn repeated_refusal_cancellation_cannot_grow_the_queue() {
    use core::future::Future as _;
    use core::task::{Context, Poll, Waker};

    let open_pkt =
        |remote_id: u32, dest: &[u8]| Packet::new(Command::Open, remote_id, 0, dest.to_vec());

    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new().with_max_channels(2),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    for id in [70, 71, 72] {
        let dest = alloc::format!("tcp:{id}\0");
        seen.feed(&open_pkt(id, dest.as_bytes()));
    }

    let shared = Arc::clone(&reader.shared);
    let wh = now(shared.write_half.lock());
    let cancel_once = |reader: &mut Reader<SharedMock, SharedMock>| {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
    };
    // First cancellation leaves the leftover 72: cap + 1.
    cancel_once(&mut reader);
    assert_eq!(reader.shared.lock_incoming().len(), 3);

    // With a new OPEN waiting on the wire, every further cancelled
    // read parks on re-refusing the leftover and takes nothing in:
    // the queue must not grow past cap + 1.
    seen.feed(&open_pkt(73, b"tcp:73\0"));
    for _ in 0..3 {
        cancel_once(&mut reader);
        assert_eq!(
            reader.shared.lock_incoming().len(),
            3,
            "a repeated cancellation grew the supposedly bounded queue"
        );
    }

    // Once a read is allowed to finish, the leftover is refused
    // first, only then is the new OPEN taken in — and refused too,
    // over the cap as it is.
    drop(wh);
    {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Err(Error::UnexpectedEof)) => {}
            other => panic!("expected the drained-transport EOF, got {other:?}"),
        }
    }
    let refused: alloc::vec::Vec<u32> = seen
        .sent()
        .iter()
        .filter(|(cmd, ..)| *cmd == Command::Close)
        .map(|&(_, _, arg1, _)| arg1)
        .collect();
    assert_eq!(refused, [72, 73], "leftover first, then the new arrival");
    let q = reader.shared.lock_incoming();
    assert_eq!(q.len(), 2, "back at the cap");
    assert_eq!(q.front().unwrap().remote, RemoteId::from(70));
}

#[test]
fn a_cancelled_overflow_refusal_keeps_the_open_recoverable() {
    use core::future::Future as _;
    use core::task::{Context, Poll, Waker};

    let open_pkt =
        |remote_id: u32, dest: &[u8]| Packet::new(Command::Open, remote_id, 0, dest.to_vec());

    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
    let seen = SharedMock::new(mock);
    // Two incoming slots: OPENs 70 and 71 fill the queue, 72
    // overflows it and has to be refused with CLSE.
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new().with_max_channels(2),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    for id in [70, 71, 72] {
        let dest = alloc::format!("tcp:{id}\0");
        seen.feed(&open_pkt(id, dest.as_bytes()));
    }

    // Hold the write lock, so the refusal's CLSE cannot start —
    // the exact window a cancel lands in.
    let shared = Arc::clone(&reader.shared);
    let wh = now(shared.write_half.lock());
    {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        // The poll queues 70 and 71, then parks refusing 72.
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        // Drop mid-refusal — cancellation.
    }
    drop(wh);

    // The refused OPEN survived the cancel: it is back at the head
    // of the queue (one past the cap), and the connection is still
    // healthy — nothing was half-written.
    {
        let q = reader.shared.lock_incoming();
        assert_eq!(q.len(), 3, "the refused OPEN must be requeued");
        assert_eq!(q.front().unwrap().remote, RemoteId::from(72));
    }
    reader
        .shared
        .desync
        .check::<core::convert::Infallible>()
        .expect("a cancelled refusal must not poison the connection");

    // The verdict machinery now answers it: adbd gets its CLSE.
    let inc = reader.try_accept_incoming().unwrap();
    assert_eq!(inc.destination(), b"tcp:72\0");
    now(inc.reject()).unwrap();
    let (cmd, _, arg1, _) = seen.sent().last().unwrap().clone();
    assert_eq!(
        (cmd, arg1),
        (Command::Close, 72),
        "the CLSE names the refused OPEN"
    );
}

#[test]
fn a_cancelled_write_stops_both_halves() {
    // Index 1: the header is out, the payload write hangs.
    let (mut reader, writer, ch) = split_with_channel(Some(1));
    abandon(writer.write_channel(ch, b"payload-that-never-made-it"));

    let err = now(writer.write_channel(ch, b"more")).unwrap_err();
    assert!(
        matches!(err, Error::Desynchronized),
        "writer: expected Desynchronized, got {err:?}"
    );

    let mut buf = [0u8; 16];
    let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
    assert!(
        matches!(err, Error::Desynchronized),
        "reader: expected Desynchronized, got {err:?}"
    );
}

#[test]
fn a_cancelled_write_wakes_reads_waiting_on_other_channels() {
    use alloc::task::Wake;
    use core::task::{Context, Waker};

    struct Woken(AtomicBool);
    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    // Two channels; the write on `a` hangs after its header (the
    // handshake and both OPENs take the first six writes).
    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn())
        .feed(&okay(1))
        .feed(&okay(2))
        .stall_write(6 + 1);
    let conn = now(Connection::connect(
        SharedMock::new(mock),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let a = now(reader.open_channel(b"shell:\0")).unwrap();
    let b = now(reader.open_channel(b"shell:\0")).unwrap();

    let woken = Arc::new(Woken(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&woken));
    let mut buf = [0u8; 16];
    let mut read = pin!(writer.read_channel(b, &mut buf));
    assert!(read
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());

    abandon(writer.write_channel(a, b"payload-that-never-made-it"));
    assert!(
        woken.0.load(Ordering::Relaxed),
        "the read on b slept through the desync"
    );
    let err = now(read).unwrap_err();
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

#[test]
fn a_ready_without_credit_fails_a_writer_open_on_a_reader_driven_connection() {
    use crate::error::ProtocolError;
    use core::task::{Context, Waker};

    // Queued behind the first channel's grant: the device's answer
    // to the Writer's OPEN (local id 2), without its credit.
    let (mut reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(
        64,
        &[Packet::new(Command::Ready, 43, 2, Vec::new())],
    );
    let mut open = pin!(writer.open_channel(b"svc:\0"));
    assert!(open
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());

    // The reader-driven call that happens to read the READY gets
    // the fault, as such calls do ...
    let mut buf = [0u8; 8];
    let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
    assert!(
        matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
        "reader: got {err:?}"
    );
    // ... and the opener hears of it too, instead of waiting on.
    let err = now(open).unwrap_err();
    assert!(
        matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
        "opener: got {err:?}"
    );
    let (cmd, arg0, arg1, _) = seen.sent().last().unwrap().clone();
    assert_eq!((cmd, arg0, arg1), (Command::Close, 2, 43));
}

#[test]
fn a_read_dropped_waiting_for_the_ack_lock_takes_nothing() {
    use core::task::{Context, Waker};

    let (_reader, writer, ch, _seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    // Five bytes dispatched and not yet acknowledged, as `run`
    // leaves them under delayed ACK.
    {
        let mut chs = writer.shared.lock_channels();
        let slot = chs.get_mut(ch).unwrap();
        assert!(matches!(slot.apply_write(b"hello"), Ok(AckDecision::Hold)));
    }
    // Another task is mid-packet, so the read's OKAY has to wait.
    let wh = now(writer.shared.write_half.lock());
    let mut buf = [0u8; 8];
    {
        let mut read = pin!(writer.read_channel(ch, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    {
        let chs = writer.shared.lock_channels();
        let slot = chs.get(ch).unwrap();
        assert_eq!(
            (slot.buffered(), slot.unacked()),
            (5, 5),
            "a read dropped while waiting took the bytes"
        );
    }
    drop(wh);
    let n = now(writer.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"hello");
}

/// What a reader-driven read took off the wire stays in the channel
/// until the read can have it, so a call dropped while it waits to
/// acknowledge leaves the next one the bytes and the OKAY.
#[test]
fn a_reader_dropped_waiting_for_the_ack_lock_keeps_the_packet() {
    use core::task::{Context, Waker};

    let (mut reader, writer, ch, seen) =
        crate::base::mock::split_one_channel_delayed_ack(64, &[wrte(1, b"hello")]);
    // Another task is mid-packet, so the read's OKAY has to wait.
    let wh = now(writer.shared.write_half.lock());
    let mut buf = [0u8; 8];
    {
        let mut read = pin!(reader.read_channel(ch, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    drop(wh);
    {
        let chs = writer.shared.lock_channels();
        let slot = chs.get(ch).unwrap();
        assert_eq!(
            (slot.buffered(), slot.unacked()),
            (5, 5),
            "a read dropped while waiting took the packet with it"
        );
    }
    assert!(seen.acks_for(1).is_empty(), "nothing was taken yet");

    let n = now(reader.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(seen.acks_for(1), [5]);
}

/// A zero-length WRTE delivers nothing, so a read goes on to the next
/// packet rather than come back with a zero that means nothing either.
#[test]
fn a_reader_reads_past_a_zero_length_write() {
    let (mut reader, _writer, ch, _seen) =
        crate::base::mock::split_one_channel_delayed_ack(64, &[wrte(1, b""), wrte(1, b"after it")]);
    let mut buf = [0u8; 16];
    let n = now(reader.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"after it");
}

/// Without delayed ACK the empty packet still has its OKAY coming: the
/// device sends nothing more on the channel until it arrives.
#[test]
fn a_zero_length_write_is_still_acknowledged_without_delayed_ack() {
    let (mut reader, _writer, ch) = split_with_channel(None);
    let seen = now(reader.shared.write_half.lock()).clone();
    seen.feed(&wrte(1, b""));
    seen.feed(&wrte(1, b"after it"));

    let mut buf = [0u8; 16];
    let n = now(reader.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"after it");
    assert_eq!(seen.acks_for(1).len(), 2);
}

/// The packet a read asks for goes through the slot whole, and the cap
/// never drops below a packet. Read in pieces, as `deliver` served it.
#[test]
fn a_full_packet_fits_a_channel_with_the_smallest_receive_cap() {
    let config = ConnectionConfig::new()
        .with_max_payload(1024)
        .with_max_rx_per_channel(1);
    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn_with("delayed_ack"))
        .feed(&crate::base::mock::okay_with_budget(1, 64))
        .feed(&wrte(1, &[0xAB; 1024]));
    let conn = now(Connection::connect(
        SharedMock::new(mock),
        NoAuth,
        HostBanner::Raw(b"host::features=delayed_ack"),
        config,
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();

    let mut got = Vec::new();
    while got.len() < 1024 {
        let mut buf = [0u8; 100];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, [0xAB; 1024]);
}

#[test]
fn an_opener_dropped_after_its_ready_was_taken_still_closes_the_channel() {
    use core::task::{Context, Waker};

    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn())
        .feed(&okay(1))
        // The device accepts the Writer's OPEN (local id 2), then
        // writes on the first channel.
        .feed(&Packet::new(Command::Ready, 43, 2, Vec::new()))
        .feed(&Packet::new(Command::Write, 42, 1, b"x".to_vec()));
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    {
        let mut open = pin!(writer.open_channel(b"svc:\0"));
        assert!(open
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        // Another call takes the READY; the opener never looks again.
        let mut buf = [0u8; 4];
        assert_eq!(now(reader.read_channel(ch, &mut buf)).unwrap(), 1);
    }

    // The next packet anyone writes goes out behind the owed CLSE.
    now(writer.write_channel(ch, b"y")).unwrap();
    let sent = seen.sent();
    let tail: Vec<_> = sent[sent.len() - 2..]
        .iter()
        .map(|(cmd, arg0, arg1, _)| (*cmd, *arg0, *arg1))
        .collect();
    assert_eq!(tail, [(Command::Close, 2, 43), (Command::Write, 1, 42)]);
}

#[test]
fn a_fault_closes_the_device_end_even_once_the_slot_is_gone() {
    // The opener was given up on between the fault and this: its
    // slot is free, but the device still holds the channel open.
    let (reader, _writer, _ch) = split_with_channel(None);
    let seen = reader.shared.write_half.try_lock().unwrap().clone();
    let ids = ChannelIds {
        local: LocalId::from(99),
        remote: RemoteId::from(77),
    };
    now(reader.shared.fail_channel(5, ids, ChannelFault::RxOverflow)).unwrap();
    let (cmd, arg0, arg1, _) = seen.sent().last().unwrap().clone();
    assert_eq!((cmd, arg0, arg1), (Command::Close, 99, 77));
}

#[test]
fn a_read_that_owes_no_ack_does_not_wait_for_the_write_lock() {
    // Without delayed ACK, a 1 KiB watermark.
    let config = ConnectionConfig::new()
        .with_max_payload(1024)
        .with_initial_ack_bytes(1024);
    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
    let conn = now(Connection::connect(
        SharedMock::new(mock),
        NoAuth,
        HostBanner::Features(&[]),
        config,
    ))
    .unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    // Well past the watermark, with its acknowledgement held back.
    {
        let mut chs = writer.shared.lock_channels();
        let slot = chs.get_mut(ch).unwrap();
        // The first is acknowledged on arrival, the second takes the
        // channel past the watermark and is held.
        slot.apply_write(&[0xEE; 1000]).unwrap();
        slot.apply_write(&[0xEE; 1000]).unwrap();
    }

    // Another task holds the write half; a small read leaves the
    // buffer past the watermark, so it owes nothing and goes ahead.
    let _wh = now(writer.shared.write_half.lock());
    let mut buf = [0u8; 8];
    assert_eq!(now(writer.read_channel(ch, &mut buf)).unwrap(), 8);
    let chs = writer.shared.lock_channels();
    assert_eq!(chs.get(ch).unwrap().unacked(), 1000);
}

/// A write given up on says nothing about bytes the device already
/// delivered: the read gets them, and the next one the failure.
#[test]
fn a_read_woken_on_a_desynchronized_connection_hands_out_what_arrived() {
    use core::task::{Context, Waker};

    // Index 1: the header is out, the payload write hangs.
    let (_reader, writer, ch) = split_with_channel(Some(1));
    let mut buf = [0u8; 8];
    let n = {
        let mut read = pin!(writer.read_channel(ch, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());

        // Data lands while another task abandons a packet mid-write.
        hold_back(&writer, ch, b"hi");
        abandon(writer.write_channel(ch, b"payload-that-never-made-it"));

        now(read).unwrap()
    };
    assert_eq!(&buf[..n], b"hi");

    let err = now(writer.read_channel(ch, &mut buf)).unwrap_err();
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// Put `data` in `ch`'s buffer as `run` leaves it under delayed ACK:
/// waiting for a read, its OKAY held back until then.
fn hold_back<WH: embedded_io_async::Write>(writer: &Writer<WH>, ch: ChannelId, data: &[u8]) {
    let mut chs = writer.shared.lock_channels();
    chs.get_mut(ch).unwrap().apply_write(data).unwrap();
}

/// The failure of an OKAY is the connection's and not the read's, whose
/// bytes the device delivered all the same.
#[test]
fn a_failed_okay_costs_the_read_nothing() {
    let (_reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    hold_back(&writer, ch, b"hello world");
    seen.fail_writes(ErrorKind::Other);

    let mut buf = [0u8; 5];
    assert_eq!(now(writer.read_channel(ch, &mut buf)).unwrap(), 5);
    assert_eq!(&buf, b"hello");

    let mut rest = [0u8; 16];
    let n = now(writer.read_channel(ch, &mut rest)).unwrap();
    assert_eq!(&rest[..n], b" world", "the rest comes first");
    let err = now(writer.read_channel(ch, &mut rest)).unwrap_err();
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// Writes fail like this once the device is gone, which leaves no
/// stream to fall out of step with: reads go on to what it sent before
/// it went, here and on the wire.
#[test]
fn an_okay_to_a_device_that_is_gone_desynchronizes_nothing() {
    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::BrokenPipe,
        ErrorKind::NotConnected,
    ] {
        let (mut reader, writer, ch, seen) =
            crate::base::mock::split_one_channel_delayed_ack(64, &[]);
        hold_back(&writer, ch, b"hello");
        seen.fail_writes(kind);

        let mut buf = [0u8; 16];
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"hello", "{kind:?}");
        writer
            .shared
            .desync
            .check::<core::convert::Infallible>()
            .unwrap_or_else(|_| panic!("{kind:?} raised a desync"));

        seen.feed(&wrte(1, b"from the wire"));
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"from the wire", "{kind:?}");
    }
}

/// An unknown failure is no such thing: the device may be there, and
/// reading the rest of a packet from whatever comes next.
#[test]
fn an_okay_that_fails_otherwise_desynchronizes() {
    let (_reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    hold_back(&writer, ch, b"hello");
    seen.fail_writes(ErrorKind::TimedOut);

    let mut buf = [0u8; 16];
    now(writer.read_channel(ch, &mut buf)).unwrap();
    assert!(writer
        .shared
        .desync
        .check::<core::convert::Infallible>()
        .is_err());
}

/// Without delayed ACK the OKAY goes out as the packet is dispatched,
/// and a read cannot be left to fail with the packet still in the slot.
#[test]
fn a_reader_hands_over_a_packet_whose_okay_failed() {
    let (mut reader, _writer, ch) = split_with_channel(None);
    let seen = now(reader.shared.write_half.lock()).clone();
    seen.feed(&wrte(1, b"hello"));
    seen.fail_writes(ErrorKind::Other);

    let mut buf = [0u8; 16];
    let n = now(reader.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"hello");
    let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// Taking the bytes ahead of the write would lose them with the call,
/// and the next read, which a desync no longer stops, would come back
/// past the gap with no word of it.
#[test]
fn a_read_dropped_writing_its_okay_leaves_no_gap() {
    let (_reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    hold_back(&writer, ch, b"hello world");
    seen.stall_writes();

    let mut buf = [0u8; 5];
    abandon(writer.read_channel(ch, &mut buf));

    let mut got = Vec::new();
    let mut rest = [0u8; 16];
    let err = loop {
        match now(writer.read_channel(ch, &mut rest)) {
            Ok(n) => got.extend_from_slice(&rest[..n]),
            Err(e) => break e,
        }
    };
    assert_eq!(got, b"hello world");
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// An OKAY lets the device send as much again, and `run` takes that in
/// with the write still finishing. It owes an OKAY of its own, which a
/// read taking it along would leave unsent, and the credit gone for good.
#[test]
fn what_lands_during_an_okay_keeps_the_okay_it_owes() {
    use core::task::{Context, Waker};

    let (_reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    hold_back(&writer, ch, b"hello");
    seen.slow_writes(1);

    let mut buf = [0u8; 16];
    let n = {
        let mut read = pin!(writer.read_channel(ch, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        hold_back(&writer, ch, b" world");
        now(read).unwrap()
    };
    assert_eq!(&buf[..n], b"hello");

    let n = now(writer.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b" world");
    assert_eq!(seen.acks_for(1), [5, 6], "credit for every byte read");
}

/// Read `ch` with the OKAY for `packets[0]` held up on its way out, a
/// second read taking the bytes it settled, and `packets[1]` landing in
/// their place before it gets out. The first read has nothing left of
/// what it settled, and what it finds instead owes an OKAY of its own.
fn read_overtaken_during_its_okay(
    reader: &mut Reader<SharedMock, SharedMock>,
    writer: &Writer<SharedMock>,
    ch: ChannelId,
    seen: &SharedMock,
    packets: [&[u8]; 2],
) {
    use core::task::{Context, Waker};

    seen.feed(&wrte(1, packets[0]));
    now(reader.dispatch_one()).unwrap();
    seen.slow_writes(1);

    let second = writer.clone();
    let mut buf = [0u8; 2048];
    let n = {
        let mut read = pin!(writer.read_channel(ch, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());

        let mut settled = [0u8; 2048];
        let n = now(second.read_channel(ch, &mut settled)).unwrap();
        assert_eq!(&settled[..n], packets[0]);

        seen.feed(&wrte(1, packets[1]));
        now(reader.dispatch_one()).unwrap();

        now(read).unwrap()
    };
    assert_eq!(&buf[..n], packets[1]);

    let chs = writer.shared.lock_channels();
    let slot = chs.get(ch).unwrap();
    assert_eq!(slot.buffered(), 0);
    assert_eq!(slot.unacked(), 0, "bytes gone with no OKAY for them");
}

/// Under delayed ACK nothing would acknowledge those bytes later: with
/// the buffer empty no read has anything to settle, and the credit they
/// took is gone for good.
#[test]
fn a_read_overtaken_during_its_okay_owes_what_it_takes_instead() {
    let (mut reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    read_overtaken_during_its_okay(&mut reader, &writer, ch, &seen, [b"hello", b" world"]);
    assert_eq!(seen.acks_for(1), [5, 6], "credit for every byte read");
}

/// Without delayed ACK a packet that reaches the watermark holds back
/// its OKAY for a read, and it is the one OKAY the device waits for
/// before it sends another: going without stops the channel.
#[test]
fn a_read_overtaken_during_its_okay_owes_what_it_takes_instead_without_delayed_ack() {
    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new()
            .with_max_payload(1024)
            .with_initial_ack_bytes(1024),
    ))
    .unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();

    let packets: [&[u8]; 2] = [&[0xAA; 1024], &[0xBB; 1024]];
    read_overtaken_during_its_okay(&mut reader, &writer, ch, &seen, packets);
    assert_eq!(seen.acks_for(1), [0, 0], "an OKAY for each packet");
}

/// A stalled write half does not hold up what no OKAY can come of. A
/// read that tried would never finish here: every write stalls.
#[test]
fn a_desynchronized_connection_is_sent_no_okay() {
    let (_reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    seen.stall_writes();
    abandon(writer.write_channel(ch, b"payload-that-never-made-it"));
    hold_back(&writer, ch, b"hello");

    let mut buf = [0u8; 16];
    let n = now(writer.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"hello");
}

#[test]
fn a_connection_nobody_reads_is_sent_no_okay() {
    let (reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    hold_back(&writer, ch, b"hello");
    drop(reader);
    seen.stall_writes();

    let mut buf = [0u8; 16];
    let n = now(writer.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"hello");
    let err = now(writer.read_channel(ch, &mut buf)).unwrap_err();
    assert!(matches!(err, Error::Disconnected), "got {err:?}");
}

/// What a closed channel still holds owes nothing, so a read of it waits
/// for no write half, however busy that is.
#[test]
fn a_closed_channel_is_read_without_the_write_half() {
    let (_reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    hold_back(&writer, ch, b"hello");
    writer
        .shared
        .lock_channels()
        .get_mut(ch)
        .unwrap()
        .apply_close();

    let busy = now(writer.shared.write_half.lock());
    let mut buf = [0u8; 16];
    let n = now(writer.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"hello");
    drop(busy);
    assert!(seen.acks_for(1).is_empty());
}

#[test]
fn writes_that_complete_leave_both_halves_working() {
    let (mut reader, writer, ch) = split_with_channel(None);
    now(writer.write_channel(ch, b"payload")).unwrap();
    let mut buf = [0u8; 16];
    // Nothing left to read, but the call is refused for that reason
    // rather than for a broken stream.
    assert!(!matches!(
        now(reader.read_channel(ch, &mut buf)),
        Err(Error::Desynchronized)
    ));
}

/// What a packet owes the device outlives the call that took it in: a
/// call dropped behind a busy writer leaves it to go out ahead of
/// whatever comes next, in the order it fell due.
mod debt_tests {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use embedded_io::ErrorKind;

    use crate::base::channel::ChannelId;
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        abandon, cnxn, now, okay, split_two_channels_delayed_ack, split_with_channel, wrte, Mock,
        NoAuth, SharedMock, FAILED_WRITES,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::Error;

    use super::{Reader, SplitIncoming, Writer};

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// Drop `fut` where its first poll leaves it, as a timeout would.
    fn dropped_parked<F: Future>(fut: F) {
        assert!(poll_once(Box::pin(fut).as_mut()).is_pending());
    }

    fn seen_by(writer: &Writer<SharedMock>) -> SharedMock {
        now(writer.shared.write_half.lock()).clone()
    }

    /// CLSEs the halves sent, as (our end, the device's end).
    fn closes(seen: &SharedMock) -> Vec<(u32, u32)> {
        seen.sent()
            .into_iter()
            .filter(|(cmd, ..)| *cmd == Command::Close)
            .map(|(_, arg0, arg1, _)| (arg0, arg1))
            .collect()
    }

    /// The device's READY for an end of ours that nobody waits on any
    /// more: an OPEN given up on before the answer.
    fn stray_ready(local_id: u32) -> Packet {
        Packet::new(Command::Ready, 43, local_id, Vec::new())
    }

    #[test]
    fn an_okay_survives_a_read_dropped_behind_a_busy_writer() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&wrte(1, b"hello"));

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 16];
        dropped_parked(reader.read_channel(ch, &mut buf));
        drop(busy);
        assert!(seen.acks_for(1).is_empty(), "the write half was busy");

        // A read with its data in hand has no packet to wait for, and
        // the device, with no OKAY, has no reason to send one.
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(seen.acks_for(1).len(), 1);

        seen.feed(&wrte(1, b"further traffic"));
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"further traffic");
        assert_eq!(seen.acks_for(1).len(), 2);
    }

    #[test]
    fn a_close_for_a_ready_survives_a_read_dropped_behind_a_busy_writer() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&stray_ready(7));

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 16];
        dropped_parked(reader.read_channel(ch, &mut buf));
        drop(busy);
        assert!(closes(&seen).is_empty(), "the write half was busy");

        seen.feed(&wrte(1, b"further traffic"));
        now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(closes(&seen), [(7, 43)]);
    }

    /// A READY without its credit breaks channel 1, and the device still
    /// holds an end it takes for open.
    #[test]
    fn a_close_for_a_fault_survives_a_call_dropped_behind_a_busy_writer() {
        let (mut reader, _a, _b, seen) =
            split_two_channels_delayed_ack(&[Packet::new(Command::Ready, 42, 1, Vec::new())]);
        let shared = Arc::clone(&reader.shared);

        let busy = now(shared.write_half.lock());
        dropped_parked(reader.dispatch_one());
        drop(busy);
        assert!(closes(&seen).is_empty(), "the write half was busy");

        seen.feed(&wrte(2, b"further traffic"));
        now(reader.dispatch_one()).unwrap();
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    /// `dispatch_one` waits for a packet however long one takes, and the
    /// device, owed an OKAY, may have no reason to send one. Read here
    /// as the end of the mock: the debt has to be out by then.
    #[test]
    fn a_call_pays_before_it_waits_for_a_packet() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&stray_ready(7));

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 16];
        dropped_parked(reader.read_channel(ch, &mut buf));
        drop(busy);

        let _ = now(reader.dispatch_one());
        assert_eq!(closes(&seen), [(7, 43)]);
    }

    /// The opener goes after the read that took its packets, so the
    /// CLSE falls due behind the OKAY for the same channel, and a list
    /// paid from the wrong end would close the channel first.
    #[test]
    fn what_is_owed_goes_out_in_the_order_it_fell_due() {
        let mut mock = Mock::new();
        mock.feed(&cnxn())
            .feed(&okay(1))
            .feed(&Packet::new(Command::Ready, 43, 2, Vec::new()))
            .feed(&Packet::new(Command::Write, 43, 2, b"x".to_vec()));
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        let seen = seen_by(&writer);
        let mut open = Box::pin(writer.open_channel(b"svc:\0"));
        assert!(poll_once(open.as_mut()).is_pending());

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 16];
        dropped_parked(reader.read_channel(ch, &mut buf));
        drop(open);
        drop(busy);

        now(writer.write_channel(ch, b"y")).unwrap();
        let sent = seen.sent();
        let tail: Vec<_> = sent[sent.len() - 3..]
            .iter()
            .map(|(cmd, arg0, arg1, _)| (*cmd, *arg0, *arg1))
            .collect();
        assert_eq!(
            tail,
            [
                (Command::Ready, 2, 43),
                (Command::Close, 2, 43),
                (Command::Write, 1, 42)
            ]
        );
    }

    /// What bounds the list: nothing more comes in until it is paid, so
    /// a call dropped over and over adds nothing, with more waiting.
    #[test]
    fn repeated_cancellation_cannot_grow_what_is_owed() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        for local_id in 10..14 {
            seen.feed(&stray_ready(local_id));
        }

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 16];
        for _ in 0..3 {
            dropped_parked(reader.read_channel(ch, &mut buf));
            assert_eq!(writer.shared.lock_owed().len(), 1);
        }
        drop(busy);

        for _ in 0..4 {
            let _ = now(reader.dispatch_one());
        }
        assert_eq!(closes(&seen), [(10, 43), (11, 43), (12, 43), (13, 43)]);
    }

    /// Only the wait for the write half can be walked away from: past
    /// that the packet is on its way out, and a drop abandons it.
    #[test]
    fn a_payment_dropped_mid_write_desynchronizes() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&wrte(1, b"hello"));
        seen.stall_writes();

        let mut buf = [0u8; 16];
        abandon(reader.read_channel(ch, &mut buf));
        assert!(writer
            .shared
            .desync
            .check::<core::convert::Infallible>()
            .is_err());
    }

    /// Nothing reaches a device that is gone, and what it sent before it
    /// went is still to be received past the debt that cannot be paid.
    #[test]
    fn what_is_owed_to_a_device_that_is_gone_is_written_off() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&wrte(1, b"one"));
        seen.feed(&stray_ready(7));
        seen.feed(&wrte(1, b"two"));
        seen.fail_writes(ErrorKind::BrokenPipe);

        let mut buf = [0u8; 16];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"one");
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"two");
        assert!(writer.shared.lock_owed().is_empty());
    }

    /// `run` refuses what nobody listens for ahead of every receive. The
    /// refusal fails, which takes the request with it, and giving up
    /// there would leave the packets behind it unread.
    #[test]
    fn a_refusal_to_a_device_that_is_gone_stops_nothing() {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        now(reader.dispatch_one()).unwrap();
        now(reader.dispatch_one()).unwrap();
        seen.feed(&wrte(1, b"behind it"));
        seen.fail_writes(ErrorKind::BrokenPipe);

        assert!(matches!(
            now(reader.run()),
            Err(crate::error::Error::UnexpectedEof)
        ));
        assert_eq!(writer.shared.lock_incoming().len(), 0);
        let mut buf = [0u8; 16];
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"behind it");
    }

    /// An OPEN past the cap is refused as it lands, and that refusal
    /// failing is no reason for the call that took it in to fail: the
    /// packets behind it are still to be read.
    #[test]
    fn a_refusal_on_arrival_to_a_device_that_is_gone_stops_nothing() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        now(reader.open_channel(b"shell:\0")).unwrap();
        let seen = seen_by(&writer);
        for id in [70, 71] {
            let dest = alloc::format!("tcp:{id}\0");
            seen.feed(&Packet::new(Command::Open, id, 0, dest.into_bytes()));
        }
        seen.fail_writes(ErrorKind::BrokenPipe);

        now(reader.dispatch_one()).unwrap();
        now(reader.dispatch_one()).unwrap();
    }

    /// The same for what a cancelled refusal left past the cap.
    #[test]
    fn a_refusal_past_the_cap_to_a_device_that_is_gone_stops_nothing() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        let seen = seen_by(&writer);
        for id in [70, 71] {
            let dest = alloc::format!("tcp:{id}\0");
            seen.feed(&Packet::new(Command::Open, id, 0, dest.into_bytes()));
        }

        // The refusal of the second, dropped waiting for the write half,
        // leaves it past the cap.
        now(reader.dispatch_one()).unwrap();
        let busy = now(writer.shared.write_half.lock());
        dropped_parked(reader.dispatch_one());
        drop(busy);

        seen.feed(&wrte(1, b"behind it"));
        seen.fail_writes(ErrorKind::BrokenPipe);
        now(reader.dispatch_one()).unwrap();
        assert_eq!(writer.shared.lock_incoming().len(), 1, "back at the cap");
        let mut buf = [0u8; 16];
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"behind it");
    }

    /// Reception carries on once the device is gone, to what it sent
    /// before it went, and that may be more OPENs than the queue has room
    /// for. Each refusal fails. Were it to go back, each would land one
    /// past the cap, and hold on to its destination.
    #[test]
    fn opens_from_a_device_that_is_gone_stay_within_the_budget() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(2),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        let seen = seen_by(&writer);
        let _listener = writer.listen_incoming();
        for id in 70..76 {
            let dest = alloc::format!("tcp:{id}\0");
            seen.feed(&Packet::new(Command::Open, id, 0, dest.into_bytes()));
        }
        seen.feed(&wrte(1, b"behind them"));
        seen.fail_writes(ErrorKind::BrokenPipe);

        assert!(matches!(now(reader.run()), Err(Error::UnexpectedEof)));
        assert_eq!(writer.shared.lock_incoming().len(), 2);
        let mut buf = [0u8; 16];
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"behind them");
    }

    /// A request for a verdict, with every slot of its connection taken.
    fn request_with_no_slot_left() -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        SplitIncoming<SharedMock>,
        SharedMock,
    ) {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        now(reader.open_channel(b"shell:\0")).unwrap();
        let seen = seen_by(&writer);
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        let incoming = now(reader.accept_incoming()).unwrap();
        (reader, writer, incoming, seen)
    }

    /// A device that is gone leaves nobody to refuse, so the request goes,
    /// and the call still fails. Any other failure says nothing of the
    /// kind: the request is back for another verdict.
    #[test]
    fn a_reject_that_fails_keeps_the_request_unless_the_device_is_gone() {
        for (kind, left) in FAILED_WRITES {
            let (_reader, writer, incoming, seen) = request_with_no_slot_left();
            seen.fail_writes(kind);

            let err = now(incoming.reject()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            assert_eq!(writer.shared.lock_incoming().len(), left, "{kind:?}");
        }
    }

    /// With no slot to give, an accept is a refusal, and goes the same
    /// way.
    #[test]
    fn an_accept_with_no_slot_that_fails_keeps_the_request_unless_the_device_is_gone() {
        for (kind, left) in FAILED_WRITES {
            let (_reader, writer, incoming, seen) = request_with_no_slot_left();
            seen.fail_writes(kind);

            let err = now(incoming.accept()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            assert_eq!(writer.shared.lock_incoming().len(), left, "{kind:?}");
        }
    }

    /// A request queued for a verdict, with a slot free to take it in and
    /// a packet behind it still to be received.
    fn request_with_a_packet_behind_it() -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
        SharedMock,
    ) {
        let (mut reader, writer, ch) = split_with_channel(None);
        let seen = seen_by(&writer);
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        now(reader.dispatch_one()).unwrap();
        now(reader.dispatch_one()).unwrap();
        seen.feed(&wrte(1, b"behind it"));
        (reader, writer, ch, seen)
    }

    /// A READY that finds the device gone leaves nobody to take the
    /// channel, so the request goes, and a listener that carries on waits
    /// for the end of the connection like anyone else, rather than be
    /// handed the same request for ever. Any other failure leaves the
    /// request in the queue, behind the desync it raised.
    #[test]
    fn an_accept_that_fails_keeps_the_request_from_a_listener_unless_the_device_is_gone() {
        for (kind, left) in FAILED_WRITES {
            let (reader, writer, _ch, seen) = request_with_a_packet_behind_it();
            let listener = writer.listen_incoming();
            let incoming = now(listener.accept()).unwrap();
            seen.fail_writes(kind);

            let err = now(incoming.accept()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            assert_eq!(writer.shared.lock_channels().in_use(), 1, "{kind:?}");

            let mut next = Box::pin(listener.accept());
            if left == 0 {
                assert!(poll_once(next.as_mut()).is_pending(), "{kind:?}");
                assert!(matches!(now(reader.run()), Err(Error::UnexpectedEof)));
                assert!(matches!(now(next), Err(Error::Disconnected)), "{kind:?}");
            } else {
                assert!(matches!(now(next), Err(Error::Desynchronized)), "{kind:?}");
            }
            assert_eq!(writer.shared.lock_incoming().len(), left, "{kind:?}");
        }
    }

    /// The same for a reader, which only gets to what the device sent
    /// before it went, and to the end of that, with the request out of
    /// the way.
    #[test]
    fn an_accept_that_fails_keeps_the_request_from_a_reader_unless_the_device_is_gone() {
        for (kind, left) in FAILED_WRITES {
            let (mut reader, writer, ch, seen) = request_with_a_packet_behind_it();
            let incoming = now(reader.accept_incoming()).unwrap();
            seen.fail_writes(kind);

            let err = now(incoming.accept()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            assert_eq!(writer.shared.lock_channels().in_use(), 1, "{kind:?}");

            let next = now(reader.accept_incoming()).map(|_| ()).unwrap_err();
            if left == 0 {
                assert!(matches!(next, Error::UnexpectedEof), "{kind:?}: {next:?}");
                let mut buf = [0u8; 16];
                let n = now(writer.read_channel(ch, &mut buf)).unwrap();
                assert_eq!(&buf[..n], b"behind it", "{kind:?}");
            } else {
                assert!(matches!(next, Error::Desynchronized), "{kind:?}: {next:?}");
            }
            assert_eq!(writer.shared.lock_incoming().len(), left, "{kind:?}");
        }
    }
}

/// The wait for the write half is a cancellation point callers are
/// promised, so it writes nothing, whatever is owed: what they go on to
/// write is their own packet alone, and what is owed stays for a call
/// that writes as a matter of course.
mod lock_wait_tests {
    use alloc::boxed::Box;
    use core::convert::Infallible;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::ids::{ChannelIds, LocalId, RemoteId};
    use crate::base::mock::{
        cnxn, now, okay, split_one_channel_delayed_ack, Mock, NoAuth, SharedMock,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;

    use super::super::shared::Owed;
    use super::{hold_back, Reader, SplitIncoming, Writer};

    /// The device's end of a channel the host owes a CLSE.
    const OWED_TO: u32 = 44;

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// Poll `fut` once and drop it where that leaves it, as a timeout
    /// would, and say whether it was done by then.
    fn one_poll<F: Future>(fut: F) -> bool {
        poll_once(Box::pin(fut).as_mut()).is_ready()
    }

    fn owe_a_close(writer: &Writer<SharedMock>) {
        writer.shared.owe(Owed::Close(ChannelIds {
            local: LocalId::from(9),
            remote: RemoteId::from(OWED_TO),
        }));
    }

    fn in_step(writer: &Writer<SharedMock>) -> bool {
        writer.shared.desync.check::<Infallible>().is_ok()
    }

    /// A request for a verdict, with a CLSE owed behind it.
    fn request_with_a_close_owed() -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        SplitIncoming<SharedMock>,
        SharedMock,
    ) {
        let (mut reader, writer, _ch, seen) = split_one_channel_delayed_ack(0, &[]);
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        let incoming = now(reader.accept_incoming()).unwrap();
        owe_a_close(&writer);
        (reader, writer, incoming, seen)
    }

    #[test]
    fn a_read_goes_past_what_is_owed() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        hold_back(&writer, ch, b"hello");
        owe_a_close(&writer);
        seen.stall_closes_to(OWED_TO);

        let mut buf = [0u8; 8];
        let done = one_poll(writer.read_channel(ch, &mut buf));
        assert!(in_step(&writer), "a dropped read abandoned a packet");
        assert!(done, "the read went for a packet not its own");
        assert_eq!(seen.acks_for(1), [5]);
        assert_eq!(writer.shared.lock_owed().len(), 1);
    }

    #[test]
    fn an_accept_goes_past_what_is_owed() {
        let (_reader, writer, incoming, seen) = request_with_a_close_owed();
        seen.stall_closes_to(OWED_TO);

        let done = one_poll(incoming.accept());
        assert!(in_step(&writer), "a dropped accept abandoned a packet");
        assert!(done, "the accept went for a packet not its own");
        let (cmd, _, remote, _) = seen.sent().last().unwrap().clone();
        assert_eq!((cmd, remote), (Command::Ready, 77));
        assert_eq!(writer.shared.lock_owed().len(), 1);
    }

    #[test]
    fn a_reject_goes_past_what_is_owed() {
        let (_reader, writer, incoming, seen) = request_with_a_close_owed();
        seen.stall_closes_to(OWED_TO);

        let done = one_poll(incoming.reject());
        assert!(in_step(&writer), "a dropped reject abandoned a packet");
        assert!(done, "the reject went for a packet not its own");
        let (cmd, _, remote, _) = seen.sent().last().unwrap().clone();
        assert_eq!((cmd, remote), (Command::Close, 77));
        assert_eq!(writer.shared.lock_owed().len(), 1);
    }

    /// With no slot to give, the accept is a refusal, and goes the same
    /// way.
    #[test]
    fn an_accept_with_no_slot_goes_past_what_is_owed() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        now(reader.open_channel(b"shell:\0")).unwrap();
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        let incoming = now(reader.accept_incoming()).unwrap();
        owe_a_close(&writer);
        seen.stall_closes_to(OWED_TO);

        let done = one_poll(incoming.accept());
        assert!(in_step(&writer), "a dropped accept abandoned a packet");
        assert!(done, "the accept went for a packet not its own");
    }

    /// On a transport that takes nothing any more a call stalls on the
    /// first thing it writes. A read that, by the time it has the write
    /// half, has nothing of its own to write has no business there: the
    /// device closed the channel while it waited, so no OKAY is owed.
    #[test]
    fn a_read_left_with_nothing_to_send_writes_nothing() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        hold_back(&writer, ch, b"hello");
        owe_a_close(&writer);
        seen.stall_writes();

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 8];
        let mut read = Box::pin(writer.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());
        writer
            .shared
            .lock_channels()
            .get_mut(ch)
            .unwrap()
            .apply_close();
        drop(busy);

        let done = poll_once(read.as_mut()).is_ready();
        drop(read);
        assert!(in_step(&writer), "a dropped read abandoned a packet");
        assert!(done, "the read went for a packet not its own");
        assert_eq!(&buf[..5], b"hello");
    }

    /// The wait itself was never the trouble, and stays safe to drop.
    #[test]
    fn a_call_dropped_waiting_for_the_write_half_abandons_nothing() {
        let (_reader, writer, incoming, seen) = request_with_a_close_owed();
        let ch = {
            let mut chs = writer.shared.lock_channels();
            let ch = chs.allocate().unwrap();
            chs.insert_accepted(ch, RemoteId::from(50), 0);
            ch
        };
        hold_back(&writer, ch, b"hello");
        seen.stall_writes();
        let busy = now(writer.shared.write_half.lock());

        let mut buf = [0u8; 8];
        assert!(!one_poll(writer.read_channel(ch, &mut buf)));
        assert!(!one_poll(incoming.accept()));
        let incoming = writer.shared.take_incoming().expect("back in the queue");
        assert!(!one_poll(incoming.reject()));
        drop(busy);
        assert!(in_step(&writer));
    }

    /// A transport that takes nothing stalls a call in its own packet,
    /// which what is owed never reached, and from which nothing can walk
    /// away: the write has been polled, and a drop abandons it. It costs
    /// the call nothing it promised to keep.
    #[test]
    fn a_read_dropped_writing_its_own_packet_desynchronizes() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        hold_back(&writer, ch, b"hello");
        owe_a_close(&writer);
        seen.stall_writes();

        let mut buf = [0u8; 8];
        assert!(!one_poll(writer.read_channel(ch, &mut buf)));
        assert!(!in_step(&writer));
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn an_accept_dropped_writing_its_own_packet_desynchronizes() {
        let (_reader, writer, incoming, seen) = request_with_a_close_owed();
        seen.stall_writes();

        assert!(!one_poll(incoming.accept()));
        assert!(!in_step(&writer));
        assert!(writer.shared.take_incoming().is_some(), "the request stays");
    }

    #[test]
    fn a_reject_dropped_writing_its_own_packet_desynchronizes() {
        let (_reader, writer, incoming, seen) = request_with_a_close_owed();
        seen.stall_writes();

        assert!(!one_poll(incoming.reject()));
        assert!(!in_step(&writer));
        assert!(writer.shared.take_incoming().is_some(), "the request stays");
    }

    /// What a call leaves owing goes with whatever writes next.
    #[test]
    fn what_a_read_left_owing_goes_out_with_the_next_write() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        hold_back(&writer, ch, b"hello");
        owe_a_close(&writer);

        let mut buf = [0u8; 8];
        now(writer.read_channel(ch, &mut buf)).unwrap();
        now(writer.write_channel(ch, b"y")).unwrap();
        let sent = seen.sent();
        let (cmd, _, remote, _) = sent[sent.len() - 2].clone();
        assert_eq!((cmd, remote), (Command::Close, OWED_TO));
        let (cmd, ..) = sent[sent.len() - 1];
        assert_eq!(cmd, Command::Write);
    }
}

mod send_queue_tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    use crate::base::channel::ChannelId;
    use crate::base::mock::{okay_with_budget, split_one_channel_delayed_ack, SharedMock};
    use crate::base::protocol::command::Command;

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        let mut cx = Context::from_waker(Waker::noop());
        fut.poll(&mut cx)
    }

    /// WRTE payloads the writer put on the wire, in order.
    fn wrte_payloads(seen: &SharedMock) -> Vec<Vec<u8>> {
        seen.sent()
            .into_iter()
            .filter(|(cmd, ..)| *cmd == Command::Write)
            .map(|(_, _, _, payload)| payload)
            .collect()
    }

    /// Feed `credit` bytes of delayed-ack budget straight into the
    /// slot and wake the queue — standing in for a device OKAY, so a
    /// test can dose grants between polls.
    fn grant(writer: &super::Writer<SharedMock>, ch: ChannelId, credit: u32) {
        {
            let mut chs = writer.shared.lock_channels();
            chs.get_mut(ch)
                .unwrap()
                .apply_ready(&credit.to_le_bytes())
                .unwrap();
        }
        writer.shared.signals[ch.slot].wake();
    }

    #[test]
    fn a_returning_writer_queues_behind_the_one_already_waiting() {
        // Zero initial credit parks both writers, in arrival order,
        // before any budget exists.
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(0, &[]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaaaaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        // A grant covering one chunk: the head sends `aaaaa` and
        // requeues for its remainder — behind the writer that was
        // already waiting.
        grant(&writer, ch, 5);
        assert!(poll_once(first.as_mut()).is_pending());

        // The shared grant arrives. Polling the returning writer first
        // must not let it drain the budget past the queue.
        grant(&writer, ch, 100);
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_ready());
        assert!(poll_once(first.as_mut()).is_ready());

        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 3, "expected three WRTEs, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"aaaaa");
        assert_eq!(
            &wrtes[1], b"bbbbb",
            "the queued writer goes before the returning one"
        );
        assert_eq!(&wrtes[2], b"aaaaa");
    }

    #[test]
    fn a_grant_is_served_in_arrival_order_not_by_the_scheduler() {
        // A budget of 5 lets the first writer send one chunk and queue
        // again behind the second; the grant that follows covers both.
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(5, &[okay_with_budget(1, 100)]);
        seen.parks_when_drained();

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaaaaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        // The reader dispatches the grant that covers everyone...
        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(reader.read_channel(ch, &mut buf));
            let _ = poll_once(read.as_mut());
        }

        // ...and polling the second writer first must not let it cut
        // into the frame the first one is still sending.
        assert!(poll_once(second.as_mut()).is_pending());
        assert!(poll_once(first.as_mut()).is_ready());
        assert!(poll_once(second.as_mut()).is_ready());

        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 3, "expected three WRTEs, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"aaaaa");
        assert_eq!(&wrtes[1], b"aaaaa");
        assert_eq!(&wrtes[2], b"bbbbb");
    }

    #[test]
    fn a_cancelled_head_hands_its_turn_to_the_next_writer() {
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(0, &[okay_with_budget(1, 50)]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        // Dropped before it ever sent a byte: the head of the queue
        // leaves, and the turn has to pass on.
        drop(first);

        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(reader.read_channel(ch, &mut buf));
            let _ = poll_once(read.as_mut());
        }

        assert!(poll_once(second.as_mut()).is_ready());
        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 1, "expected one WRTE, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"bbbbb");
    }

    #[test]
    fn a_cancelled_place_mid_queue_is_skipped_when_reached() {
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(0, &[okay_with_budget(1, 50)]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        let mut third = Box::pin(writer.write_channel(ch, b"ccccc"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());
        assert!(poll_once(third.as_mut()).is_pending());

        // A hole in the middle of the queue, not at its head.
        drop(second);

        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(reader.read_channel(ch, &mut buf));
            let _ = poll_once(read.as_mut());
        }

        assert!(poll_once(first.as_mut()).is_ready());
        assert!(poll_once(third.as_mut()).is_ready());

        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 2, "expected two WRTEs, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"aaaaa");
        assert_eq!(&wrtes[1], b"ccccc");
    }
}

mod incoming_tests {
    use crate::base::channel::ChannelId;
    use crate::base::mock::{now, split_one_channel_delayed_ack, wrte};
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;

    fn open_pkt(remote_id: u32, credit: u32, dest: &[u8]) -> Packet {
        Packet::new(Command::Open, remote_id, credit, dest.to_vec())
    }

    #[test]
    fn a_device_open_on_a_split_reader_is_accepted_and_serves_data() {
        let (mut reader, writer, _ch, seen) = split_one_channel_delayed_ack(0, &[]);
        seen.feed(&open_pkt(77, 4096, b"tcp:9090\0"));

        let incoming = now(reader.accept_incoming()).unwrap();
        assert_eq!(incoming.destination(), b"tcp:9090\0");
        let ch: ChannelId = now(incoming.accept()).unwrap();

        let (cmd, local, remote, payload) = seen.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Ready);
        assert_eq!(remote, 77);
        assert_eq!(payload.len(), 4);

        // Their data arrives on the accepted channel, and our write
        // spends the OPEN-granted budget through the split writer.
        seen.feed(&wrte(local, b"ping"));
        let mut buf = [0u8; 16];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"ping");

        now(writer.write_channel(ch, b"pong")).unwrap();
        let (cmd, l, r, payload) = seen.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Write);
        assert_eq!((l, r), (local, 77));
        assert_eq!(payload, b"pong");
    }

    #[test]
    fn a_rejected_open_on_a_split_reader_answers_clse() {
        let (mut reader, _writer, _ch, seen) = split_one_channel_delayed_ack(0, &[]);
        seen.feed(&open_pkt(88, 0, b"tcp:1\0"));

        let incoming = now(reader.accept_incoming()).unwrap();
        now(incoming.reject()).unwrap();

        let (cmd, local, remote, _) = seen.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Close);
        assert_eq!((local, remote), (0, 88));
    }
}

/// A reader-driven connection ends in a receive some call happens to be
/// making. That call gets the failure, and everyone else parked on the
/// connection has to hear of it too, or they wait for ever.
mod end_tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use embedded_io::ErrorKind;

    use crate::base::channel::ChannelId;
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        clse, cnxn, now, okay, split_one_channel_delayed_ack, wrte, Mock, MockError, NoAuth,
        SharedMock,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::{Error, ProtocolError};

    use super::{IncomingListener, Reader, Writer};

    type Waiter<'a> = Pin<Box<dyn Future<Output = (&'static str, Option<Error<MockError>>)> + 'a>>;

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// Two channels without delayed ACK and a read of `a` to go, which
    /// waits for a packet: the first has one WRTE out, so the next waits
    /// for its OKAY.
    #[allow(clippy::type_complexity)]
    fn two_channels() -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
        ChannelId,
        SharedMock,
    ) {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1)).feed(&okay(2));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let a = now(reader.open_channel(b"shell:a\0")).unwrap();
        let b = now(reader.open_channel(b"shell:b\0")).unwrap();
        now(writer.write_channel(a, b"one")).unwrap();
        seen.parks_when_drained();
        (reader, writer, a, b, seen)
    }

    /// One of everything a `Writer` waits for the device with, each
    /// polled until it does.
    fn parked<'a>(
        writer: &'a Writer<SharedMock>,
        a: ChannelId,
        b: ChannelId,
        listener: &'a IncomingListener<SharedMock>,
        buf: &'a mut [u8],
    ) -> Vec<Waiter<'a>> {
        let mut waiters: Vec<Waiter<'a>> = alloc::vec![
            Box::pin(async move { ("write", writer.write_channel(a, b"two").await.err()) }),
            Box::pin(async move { ("open", writer.open_channel(b"svc:\0").await.err()) }),
            Box::pin(async move { ("accept", listener.accept().await.err()) }),
            Box::pin(async move { ("read", writer.read_channel(b, buf).await.err()) }),
        ];
        for waiter in &mut waiters {
            assert!(poll_once(waiter.as_mut()).is_pending());
        }
        waiters
    }

    fn assert_all_disconnected(waiters: &mut [Waiter<'_>]) {
        for waiter in waiters {
            let Poll::Ready((what, err)) = poll_once(waiter.as_mut()) else {
                panic!("a waiter is still parked on a connection that ended");
            };
            assert!(matches!(err, Some(Error::Disconnected)), "{what}: {err:?}");
        }
    }

    #[test]
    fn the_end_of_the_stream_ends_every_waiter() {
        let (mut reader, writer, a, b, seen) = two_channels();
        let listener = writer.listen_incoming();
        let mut parked_buf = [0u8; 8];
        let mut waiters = parked(&writer, a, b, &listener, &mut parked_buf);

        seen.hang_up();
        let mut buf = [0u8; 8];
        let err = now(reader.read_channel(a, &mut buf)).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof), "got {err:?}");
        assert_all_disconnected(&mut waiters);
    }

    /// The kinds a dropped connection comes back as, which `ErrorKind`
    /// can tell from a timeout.
    #[test]
    fn a_connection_gone_ends_every_waiter() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
        ] {
            let (mut reader, writer, a, b, seen) = two_channels();
            let listener = writer.listen_incoming();
            let mut parked_buf = [0u8; 8];
            let mut waiters = parked(&writer, a, b, &listener, &mut parked_buf);

            seen.fail_next_read(kind);
            let mut buf = [0u8; 8];
            let err = now(reader.dispatch_one()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            let _ = &mut buf;
            assert_all_disconnected(&mut waiters);
        }
    }

    /// Past a header that does not parse, the stream has lost its place
    /// for good: every later read would find the same bytes.
    #[test]
    fn a_broken_header_ends_every_waiter() {
        let (mut reader, writer, a, b, seen) = two_channels();
        let listener = writer.listen_incoming();
        let mut parked_buf = [0u8; 8];
        let mut waiters = parked(&writer, a, b, &listener, &mut parked_buf);

        seen.feed_bytes(&[0xFF; 24]);
        let err = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        assert_all_disconnected(&mut waiters);
    }

    /// What every waiter needs, one packet each.
    fn feed_every_answer(seen: &SharedMock) {
        seen.feed(&okay(1));
        seen.feed(&Packet::new(Command::Ready, 43, 3, Vec::new()));
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        seen.feed(&wrte(2, b"hi"));
    }

    fn assert_all_answered(
        reader: &mut Reader<SharedMock, SharedMock>,
        waiters: &mut [Waiter<'_>],
    ) {
        for _ in 0..waiters.len() {
            now(reader.dispatch_one()).unwrap();
        }
        for waiter in waiters {
            let Poll::Ready((what, err)) = poll_once(waiter.as_mut()) else {
                panic!("a waiter did not get its answer");
            };
            assert!(err.is_none(), "{what}: {err:?}");
        }
    }

    /// A read timeout looks like any other failure to everything but the
    /// caller, who set it: on unix `SO_RCVTIMEO` comes back as
    /// `WouldBlock`, which is `ErrorKind::Other` here. It says nothing
    /// about the connection, so nothing ends and nobody is told.
    #[test]
    fn a_timeout_ends_nothing() {
        for kind in [
            ErrorKind::Other,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
        ] {
            let (mut reader, writer, a, b, seen) = two_channels();
            let listener = writer.listen_incoming();
            let mut parked_buf = [0u8; 8];
            let mut waiters = parked(&writer, a, b, &listener, &mut parked_buf);

            seen.fail_next_read(kind);
            let mut buf = [0u8; 8];
            let err = now(reader.read_channel(a, &mut buf)).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            for waiter in &mut waiters {
                assert!(poll_once(waiter.as_mut()).is_pending(), "{kind:?}");
            }

            feed_every_answer(&seen);
            assert_all_answered(&mut reader, &mut waiters);
        }
    }

    /// A packet with a wrong sum went whole, so the stream still has its
    /// place. The packet is lost, as it always was, and the next is
    /// read.
    #[test]
    fn a_wrong_checksum_ends_nothing() {
        let (mut reader, writer, a, b, seen) = two_channels();
        let listener = writer.listen_incoming();
        let mut parked_buf = [0u8; 8];
        let mut waiters = parked(&writer, a, b, &listener, &mut parked_buf);

        let mut packet = Vec::new();
        for word in [
            u32::from(Command::Write),
            42,
            1,
            1,
            0xBAD,
            !u32::from(Command::Write),
        ] {
            packet.extend_from_slice(&word.to_le_bytes());
        }
        packet.push(b'x');
        seen.feed_bytes(&packet);

        let err = now(reader.dispatch_one()).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::InvalidChecksum)),
            "got {err:?}"
        );
        feed_every_answer(&seen);
        assert_all_answered(&mut reader, &mut waiters);
    }

    /// What arrived goes first, on either half, and only then the end.
    #[test]
    fn what_arrived_is_read_before_the_end_comes_up() {
        let (mut reader, writer, a, b, seen) = two_channels();
        seen.feed(&wrte(2, b"for-b"));
        seen.feed(&wrte(1, b"for-a"));
        now(reader.dispatch_one()).unwrap();
        now(reader.dispatch_one()).unwrap();
        seen.hang_up();
        assert!(matches!(
            now(reader.dispatch_one()),
            Err(Error::UnexpectedEof)
        ));

        let mut buf = [0u8; 8];
        let n = now(reader.read_channel(a, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"for-a");
        let n = now(writer.read_channel(b, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"for-b");

        for ch in [a, b] {
            let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
            assert!(matches!(err, Error::Disconnected), "reader: {err:?}");
            let err = now(writer.read_channel(ch, &mut buf)).unwrap_err();
            assert!(matches!(err, Error::Disconnected), "writer: {err:?}");
        }
    }

    /// A channel with bytes that owe an OKAY, and `run` waiting for the
    /// packet behind them.
    #[allow(clippy::type_complexity)]
    fn bytes_owing_an_okay(
        data: &[u8],
    ) -> (
        Pin<Box<impl Future<Output = Result<Infallible, Error<MockError>>>>>,
        Writer<SharedMock>,
        ChannelId,
        SharedMock,
    ) {
        let (reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[wrte(1, data)]);
        seen.parks_when_drained();
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());
        (run, writer, ch, seen)
    }

    /// The end of the stream comes in with a read waiting for a write
    /// half that a stalled writer holds. What the read is after has
    /// arrived, and its OKAY has nobody left to go to.
    #[test]
    fn the_end_reaches_a_read_waiting_for_the_write_half() {
        let (mut run, writer, ch, seen) = bytes_owing_an_okay(b"hello");
        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 8];
        let mut read = Box::pin(writer.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());

        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        let n = now(read).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(seen.acks_for(1).is_empty());

        let err = now(writer.read_channel(ch, &mut buf)).unwrap_err();
        assert!(matches!(err, Error::Disconnected), "got {err:?}");
        drop(busy);
    }

    /// The same with the OKAY itself on its way into a transport that
    /// takes nothing. Giving it up keeps what it settled readable, with
    /// the rest behind it. It leaves half a packet, which stops the
    /// writes, but what ended the connection is what the calls waiting
    /// on the device hear of.
    #[test]
    fn the_end_reaches_a_read_stalled_in_its_okay() {
        let (mut run, writer, ch, seen) = bytes_owing_an_okay(b"hello world");
        let listener = writer.listen_incoming();
        let mut accept = Box::pin(listener.accept());
        assert!(poll_once(accept.as_mut()).is_pending());
        let mut open = Box::pin(writer.open_channel(b"svc:\0"));
        assert!(poll_once(open.as_mut()).is_pending());

        seen.stall_writes();
        let mut buf = [0u8; 5];
        let mut read = Box::pin(writer.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());

        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        assert_eq!(now(read).unwrap(), 5);
        assert_eq!(&buf, b"hello");
        let mut rest = [0u8; 16];
        let n = now(writer.read_channel(ch, &mut rest)).unwrap();
        assert_eq!(&rest[..n], b" world");

        let err = now(writer.read_channel(ch, &mut rest)).unwrap_err();
        assert!(matches!(err, Error::Disconnected), "read: {err:?}");
        let err = now(open).unwrap_err();
        assert!(matches!(err, Error::Disconnected), "open: {err:?}");
        assert!(matches!(now(accept), Err(Error::Disconnected)));
        let err = now(writer.write_channel(ch, b"x")).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "write: {err:?}");
    }

    /// A device that closed the channel before it went said all it had
    /// to, and the OKAY given up on after that takes nothing from it.
    #[test]
    fn a_read_stalled_in_its_okay_still_hears_the_channel_close() {
        let (mut run, writer, ch, seen) = bytes_owing_an_okay(b"hello");
        seen.stall_writes();
        let mut buf = [0u8; 8];
        let mut read = Box::pin(writer.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());

        seen.feed(&clse(1));
        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        let n = now(read).unwrap();
        assert_eq!(&buf[..n], b"hello");
        let err = now(writer.read_channel(ch, &mut buf)).unwrap_err();
        assert!(matches!(err, Error::ChannelClosed), "got {err:?}");
    }

    /// A request that cannot get a verdict out is not handed over: it
    /// would only come back, for ever, to a listener that carries on.
    #[test]
    fn a_listener_gets_no_request_once_an_okay_was_given_up_on() {
        let (mut run, writer, ch, seen) = bytes_owing_an_okay(b"hello");
        seen.feed(&Packet::new(Command::Open, 77, 0, b"tcp:80\0".to_vec()));
        let listener = writer.listen_incoming();
        assert!(poll_once(run.as_mut()).is_pending());

        seen.stall_writes();
        let mut buf = [0u8; 8];
        let mut read = Box::pin(writer.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());
        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        now(read).unwrap();

        assert!(matches!(now(listener.accept()), Err(Error::Disconnected)));
    }

    /// A write half that comes free after the end finds nobody to send
    /// the OKAY to, so it writes nothing that could stall.
    #[test]
    fn a_read_given_the_write_half_after_the_end_sends_no_okay() {
        let (mut run, writer, ch, seen) = bytes_owing_an_okay(b"hello");
        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 8];
        let mut read = Box::pin(writer.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());

        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        drop(busy);
        let n = now(read).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(seen.acks_for(1).is_empty());
    }

    /// Once the end has come up nothing goes back to the transport for
    /// more, and no call writes a packet that could only wait for an
    /// answer.
    #[test]
    fn calls_after_the_end_fail_at_once() {
        let (mut reader, writer, _a, _b, seen) = two_channels();
        seen.hang_up();
        assert!(matches!(
            now(reader.dispatch_one()),
            Err(Error::UnexpectedEof)
        ));
        let written = seen.sent().len();

        seen.feed(&okay(1));
        assert!(matches!(
            now(reader.dispatch_one()),
            Err(Error::Disconnected)
        ));
        assert!(matches!(
            now(reader.open_channel(b"svc:\0")),
            Err(Error::Disconnected)
        ));
        assert!(matches!(
            now(reader.accept_incoming()).err(),
            Some(Error::Disconnected)
        ));
        assert!(matches!(
            now(writer.open_channel(b"svc:\0")),
            Err(Error::Disconnected)
        ));
        assert_eq!(seen.sent().len(), written);
    }
}

/// A write given up on mid-packet ends the connection for good, and
/// nothing on the read side is writing to find that out by itself.
mod give_up_tests {
    use alloc::boxed::Box;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    use crate::base::channel::ChannelId;
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        abandon, cnxn_with, now, okay_with_budget, wrte, Mock, MockError, NoAuth, SharedMock,
    };
    use crate::error::Error;

    use super::{hold_back, Reader, Writer};

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// One channel with credit to write on and a transport that takes
    /// nothing, so that writing means giving a write up.
    fn stalled(
        configure: impl FnOnce(&mut Mock),
    ) -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
        SharedMock,
    ) {
        let mut mock = Mock::new();
        mock.feed(&cnxn_with("delayed_ack"))
            .feed(&okay_with_budget(1, 1024));
        configure(&mut mock);
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Raw(b"host::features=delayed_ack"),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        seen.parks_when_drained();
        seen.stall_writes();
        (reader, writer, ch, seen)
    }

    fn desynchronized<T>(polled: Poll<Result<T, Error<MockError>>>) -> bool {
        matches!(polled, Poll::Ready(Err(Error::Desynchronized)))
    }

    #[test]
    fn a_write_given_up_on_ends_run() {
        let (reader, writer, ch, _seen) = stalled(|_| {});
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        abandon(writer.write_channel(ch, b"cut short"));
        assert!(desynchronized(poll_once(run.as_mut())));

        // That is what ended it, and stays what everyone hears.
        let mut buf = [0u8; 8];
        let err = now(writer.read_channel(ch, &mut buf)).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
    }

    #[test]
    fn a_write_given_up_on_ends_a_parked_read() {
        let (mut reader, writer, ch, _seen) = stalled(|_| {});
        let mut buf = [0u8; 8];
        let mut read = Box::pin(reader.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());

        abandon(writer.write_channel(ch, b"cut short"));
        assert!(desynchronized(poll_once(read.as_mut())));
    }

    #[test]
    fn a_write_given_up_on_ends_a_parked_dispatch() {
        let (mut reader, writer, ch, _seen) = stalled(|_| {});
        let mut dispatch = Box::pin(reader.dispatch_one());
        assert!(poll_once(dispatch.as_mut()).is_pending());

        abandon(writer.write_channel(ch, b"cut short"));
        assert!(desynchronized(poll_once(dispatch.as_mut())));
    }

    #[test]
    fn a_write_given_up_on_ends_a_parked_accept() {
        let (mut reader, writer, ch, _seen) = stalled(|_| {});
        let mut accept = Box::pin(reader.accept_incoming());
        assert!(poll_once(accept.as_mut()).is_pending());

        abandon(writer.write_channel(ch, b"cut short"));
        assert!(desynchronized(poll_once(accept.as_mut())));
    }

    /// `run` can be left waiting on a read it may not drop, for which the
    /// next packet is the first chance it has.
    #[test]
    fn a_read_that_cannot_be_dropped_ends_run_at_the_next_packet() {
        let (reader, writer, ch, seen) = stalled(|mock| {
            mock.loses_cancelled_reads();
        });
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        abandon(writer.write_channel(ch, b"cut short"));
        assert!(
            poll_once(run.as_mut()).is_pending(),
            "the read in flight was given up on"
        );

        seen.feed(&wrte(1, b"next"));
        assert!(desynchronized(poll_once(run.as_mut())));
        let mut buf = [0u8; 8];
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"next", "the packet it finished on stays");
    }

    /// A connection desynchronized in any way ends it on the way in too,
    /// with the transport never asked for more.
    #[test]
    fn a_connection_already_desynchronized_ends_the_loop_of_a_read() {
        let (mut reader, writer, ch, seen) = stalled(|_| {});
        abandon(writer.write_channel(ch, b"cut short"));
        seen.feed(&wrte(1, b"on the wire"));
        hold_back(&writer, ch, b"in the slot");

        let mut buf = [0u8; 16];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"in the slot");
        let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
    }
}

/// What falls due while a call waits for a packet has nobody else to
/// send it: reads leave it alone, and the device may have nothing to
/// say until it arrives.
mod parked_receive_tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    use crate::base::channel::ChannelId;
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{cnxn, now, okay, wrte, Mock, NoAuth, SharedMock};
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::Error;

    use super::{Reader, Writer};

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// CLSEs the halves sent, as (our end, the device's end).
    fn closes(seen: &SharedMock) -> Vec<(u32, u32)> {
        seen.sent()
            .into_iter()
            .filter(|(cmd, ..)| *cmd == Command::Close)
            .map(|(_, arg0, arg1, _)| (arg0, arg1))
            .collect()
    }

    /// An opener with its READY taken in and nobody having looked yet,
    /// to give up on: that leaves a CLSE to go out, with `run` or a read
    /// the only thing left to send it.
    #[allow(clippy::type_complexity)]
    fn opener_answered(
        configure: impl FnOnce(&mut Mock),
    ) -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
        Pin<Box<impl Future + 'static>>,
        SharedMock,
    ) {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        configure(&mut mock);
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        seen.parks_when_drained();

        let opener = writer.clone();
        let mut open = Box::pin(async move { opener.open_channel(b"svc:\0").await });
        assert!(poll_once(open.as_mut()).is_pending());
        seen.feed(&Packet::new(Command::Ready, 43, 2, Vec::new()));
        now(reader.dispatch_one()).unwrap();
        (reader, writer, ch, open, seen)
    }

    #[test]
    fn a_parked_run_sends_what_falls_due() {
        let (reader, _writer, _ch, open, seen) = opener_answered(|_| {});
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        drop(open);
        assert!(poll_once(run.as_mut()).is_pending(), "and goes on waiting");
        assert_eq!(closes(&seen), [(2, 43)]);
    }

    #[test]
    fn a_parked_read_sends_what_falls_due() {
        let (mut reader, _writer, ch, open, seen) = opener_answered(|_| {});
        let mut buf = [0u8; 8];
        let mut read = Box::pin(reader.read_channel(ch, &mut buf));
        assert!(poll_once(read.as_mut()).is_pending());

        drop(open);
        assert!(poll_once(read.as_mut()).is_pending(), "and goes on waiting");
        assert_eq!(closes(&seen), [(2, 43)]);

        seen.feed(&wrte(1, b"after it"));
        assert!(poll_once(read.as_mut()).is_ready());
    }

    /// A read that cannot be dropped has to finish first, which is as
    /// long as the device takes: the same as for a write given up on.
    #[test]
    fn a_read_that_cannot_be_dropped_sends_it_at_the_next_packet() {
        let (reader, _writer, _ch, open, seen) = opener_answered(|mock| {
            mock.loses_cancelled_reads();
        });
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        drop(open);
        assert!(poll_once(run.as_mut()).is_pending());
        assert!(closes(&seen).is_empty(), "the read in flight was dropped");

        seen.feed(&wrte(1, b"next"));
        assert!(poll_once(run.as_mut()).is_pending());
        assert_eq!(closes(&seen), [(2, 43)]);
    }

    /// An opener given up on after the receive that ended the connection
    /// leaves a CLSE on the list. Nobody is left to hear it, so the way to
    /// what arrived does not lead through the write half, which here
    /// nobody lets go of.
    #[test]
    fn a_read_after_the_end_pays_nothing() {
        let (mut reader, writer, ch, open, seen) = opener_answered(|_| {});
        seen.feed(&wrte(1, b"hello"));
        seen.hang_up();
        now(reader.dispatch_one()).unwrap();
        let end = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(end, Error::UnexpectedEof), "got {end:?}");
        drop(open);
        let sent = seen.sent().len();

        let busy = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 8];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"hello");
        let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
        assert!(matches!(err, Error::Disconnected), "got {err:?}");
        drop(busy);
        assert_eq!(seen.sent().len(), sent, "nobody is left to hear it");
    }
}

/// A caller with no task for `Reader::run` asks `waits_for_credit` when
/// to read, and takes packets with `dispatch_one`.
mod driving_tests {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    use crate::base::channel::ChannelId;
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        clse, cnxn, now, okay, okay_with_budget, split_one_channel_delayed_ack,
        split_two_channels_delayed_ack, split_with_channel, wrte, Mock, NoAuth, SharedMock,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::{Error, ProtocolError};

    use super::{Reader, Writer};

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn read(reader: &mut Reader<SharedMock, SharedMock>, ch: ChannelId) -> Vec<u8> {
        let mut buf = [0u8; 16];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        buf[..n].to_vec()
    }

    /// CLSEs the halves sent, as (our end, the device's end).
    fn closes(seen: &SharedMock) -> Vec<(u32, u32)> {
        seen.sent()
            .into_iter()
            .filter(|(cmd, ..)| *cmd == Command::Close)
            .map(|(_, arg0, arg1, _)| (arg0, arg1))
            .collect()
    }

    /// Classic ACK, with one write out and its OKAY queued behind it.
    fn parked_on_okay() -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
    ) {
        let (reader, writer, ch) = split_with_channel(None);
        now(writer.write_channel(ch, b"first")).unwrap();
        (reader, writer, ch)
    }

    /// A transfer the transport has not finished is no reason to read:
    /// on USB every write is pending for that long, and nothing says a
    /// packet will come.
    #[test]
    fn a_transfer_in_flight_waits_for_no_credit() {
        // Index 0: the write of the WRTE's header hangs.
        let (_reader, writer, ch) = split_with_channel(Some(0));
        let mut write = Box::pin(writer.write_channel(ch, b"payload"));
        assert!(poll_once(write.as_mut()).is_pending());
        assert!(!writer.waits_for_credit(ch));
    }

    #[test]
    fn credit_in_hand_waits_for_none() {
        let (_reader, writer, ch) = split_with_channel(None);
        assert!(!writer.waits_for_credit(ch), "classic, nothing sent yet");

        let (_reader, writer, ch, _seen) = split_one_channel_delayed_ack(64, &[]);
        now(writer.write_channel(ch, b"some of it")).unwrap();
        assert!(!writer.waits_for_credit(ch), "delayed ACK, budget left");
    }

    #[test]
    fn a_parked_writer_waits_until_the_okay_is_dispatched() {
        let (mut reader, writer, ch) = parked_on_okay();
        assert!(
            !writer.waits_for_credit(ch),
            "the OKAY is owed, but no writer wants it yet"
        );

        let mut second = Box::pin(writer.write_channel(ch, b"second"));
        assert!(poll_once(second.as_mut()).is_pending());
        assert!(writer.waits_for_credit(ch));

        now(reader.dispatch_one()).unwrap();
        assert!(!writer.waits_for_credit(ch));
        assert!(poll_once(second.as_mut()).is_ready());
    }

    #[test]
    fn a_writer_out_of_delayed_ack_credit_waits_for_more() {
        let (mut reader, writer, ch, _seen) =
            split_one_channel_delayed_ack(5, &[okay_with_budget(1, 100)]);
        let mut write = Box::pin(writer.write_channel(ch, b"aaaaaaaaaa"));
        assert!(poll_once(write.as_mut()).is_pending());
        assert!(writer.waits_for_credit(ch), "five bytes out, five to go");

        now(reader.dispatch_one()).unwrap();
        assert!(!writer.waits_for_credit(ch));
        assert!(poll_once(write.as_mut()).is_ready());
    }

    /// The writer in flight needs polling to finish, and the device
    /// cannot answer a packet it has not had, so a read here would wait
    /// on the very write it stops. On USB the header would be out and
    /// the payload never sent; a WRTE for another channel would have
    /// the read's OKAY wait for a write half that same write holds.
    #[test]
    fn a_transfer_in_flight_holds_off_the_writer_parked_behind_it() {
        let (_reader, writer, ch) = split_with_channel(None);
        let busy = now(writer.shared.write_half.lock());
        let mut first = Box::pin(writer.write_channel(ch, b"aaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending(), "holds the credit");
        assert!(poll_once(second.as_mut()).is_pending(), "parked for it");
        assert!(!writer.waits_for_credit(ch));

        drop(busy);
        assert!(poll_once(first.as_mut()).is_ready());
        assert!(
            writer.waits_for_credit(ch),
            "the first write is out, and only its OKAY is left to wait for"
        );
    }

    /// A transfer given up on stops counting, or the writers left would
    /// never be told to read.
    #[test]
    fn a_dropped_transfer_stops_holding_off_the_writer_behind_it() {
        let (_reader, writer, ch, _seen) = split_one_channel_delayed_ack(5, &[]);
        let busy = now(writer.shared.write_half.lock());
        let mut first = Box::pin(writer.write_channel(ch, b"aaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());
        drop(busy);

        drop(first);
        assert!(poll_once(second.as_mut()).is_ready(), "takes the refund");

        let mut third = Box::pin(writer.write_channel(ch, b"c"));
        assert!(poll_once(third.as_mut()).is_pending());
        assert!(writer.waits_for_credit(ch));
    }

    #[test]
    fn a_channel_the_device_closes_waits_for_nothing() {
        let (mut reader, writer, ch, _seen) = split_one_channel_delayed_ack(0, &[clse(1)]);
        let mut write = Box::pin(writer.write_channel(ch, b"x"));
        assert!(poll_once(write.as_mut()).is_pending());
        assert!(writer.waits_for_credit(ch));

        now(reader.dispatch_one()).unwrap();
        assert!(!writer.waits_for_credit(ch));
        assert!(matches!(
            poll_once(write.as_mut()),
            Poll::Ready(Err(Error::ChannelClosed))
        ));
    }

    #[test]
    fn a_channel_closed_here_waits_for_nothing() {
        let (_reader, writer, ch, _seen) = split_one_channel_delayed_ack(0, &[]);
        let mut write = Box::pin(writer.write_channel(ch, b"x"));
        assert!(poll_once(write.as_mut()).is_pending());
        assert!(writer.waits_for_credit(ch));

        now(writer.close_channel(ch)).unwrap();
        assert!(!writer.waits_for_credit(ch));
    }

    #[test]
    fn a_dispatched_okay_reaches_the_write_parked_for_it() {
        let (mut reader, writer, ch) = parked_on_okay();
        let mut second = Box::pin(writer.write_channel(ch, b"second"));
        assert!(poll_once(second.as_mut()).is_pending());

        now(reader.dispatch_one()).unwrap();
        assert!(matches!(poll_once(second.as_mut()), Poll::Ready(Ok(()))));
    }

    /// Under delayed ACK what is buffered keeps its credit until it is
    /// read, as if a read had been waiting for it all along.
    #[test]
    fn a_wrte_stays_for_a_later_read_on_its_channel() {
        let (mut reader, a, b, seen) = split_two_channels_delayed_ack(&[wrte(2, b"for-b")]);
        now(reader.dispatch_one()).unwrap();
        assert!(seen.acks_for(2).is_empty(), "not read, so not acknowledged");

        assert_eq!(read(&mut reader, b), b"for-b");
        assert_eq!(seen.acks_for(2), alloc::vec![5]);

        seen.feed(&wrte(1, b"for-a"));
        assert_eq!(read(&mut reader, a), b"for-a");
    }

    /// `run` would refuse this OPEN with no listener alive. Here the
    /// reader is kept for `accept_incoming`, and a listener is no part
    /// of that.
    #[test]
    fn an_incoming_open_stays_queued_for_accept() {
        let (mut reader, _writer, _ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.feed(&Packet::new(Command::Open, 77, 4096, b"tcp:80\0".to_vec()));

        now(reader.dispatch_one()).unwrap();
        assert!(closes(&seen).is_empty(), "the OPEN was refused");
        let incoming = reader.try_accept_incoming().expect("the OPEN is queued");
        assert_eq!(incoming.destination(), b"tcp:80\0");
    }

    /// A READY without its credit is about channel 1 alone, whoever
    /// happens to be taking packets, so that call carries on.
    #[test]
    fn a_fault_closes_its_channel_and_nothing_else() {
        let (mut reader, a, b, seen) = split_two_channels_delayed_ack(&[
            Packet::new(Command::Ready, 42, 1, Vec::new()),
            wrte(2, b"for-b"),
        ]);

        now(reader.dispatch_one()).unwrap();
        assert_eq!(closes(&seen), [(1, 42)], "the device hears of it");
        now(reader.dispatch_one()).unwrap();
        assert_eq!(read(&mut reader, b), b"for-b");

        let mut buf = [0u8; 8];
        let err = now(reader.read_channel(a, &mut buf)).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_read_that_fails_is_the_callers_failure() {
        let (mut reader, _writer, _ch, _seen) = split_one_channel_delayed_ack(64, &[]);
        let err = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof), "got {err:?}");
    }

    #[test]
    fn a_desynchronized_connection_reads_nothing_more() {
        let (mut reader, writer, ch) = split_with_channel(Some(1));
        crate::base::mock::abandon(writer.write_channel(ch, b"cut short"));

        let err = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
    }

    /// As in `read_channel`: what a cancelled refusal left past the cap
    /// is refused before another packet comes in.
    #[test]
    fn queued_opens_past_the_cap_are_refused_first() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(2),
        ))
        .unwrap();
        let (mut reader, _writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        for id in [70, 71, 72] {
            let dest = alloc::format!("tcp:{id}\0");
            seen.feed(&Packet::new(Command::Open, id, 0, dest.into_bytes()));
        }

        // A refusal dropped while it waits for the write half leaves
        // its OPEN one past the cap.
        let shared = Arc::clone(&reader.shared);
        {
            let busy = now(shared.write_half.lock());
            let mut buf = [0u8; 8];
            let mut fut = Box::pin(reader.read_channel(ch, &mut buf));
            assert!(poll_once(fut.as_mut()).is_pending());
            drop(fut);
            drop(busy);
        }
        assert!(closes(&seen).is_empty(), "the refusal never got out");

        seen.feed(&wrte(1, b"x"));
        now(reader.dispatch_one()).unwrap();
        assert_eq!(closes(&seen), [(0, 72)]);
    }
}

mod backpressure_tests {
    use crate::base::mock::{now, split_two_channels_delayed_ack, wrte};

    #[test]
    fn a_split_reader_returns_credit_only_for_what_was_read() {
        let (mut reader, a, b, seen) =
            split_two_channels_delayed_ack(&[wrte(2, b"for-b"), wrte(1, b"for-a")]);

        let mut buf = [0u8; 32];
        now(reader.read_channel(a, &mut buf)).unwrap();
        assert!(
            seen.acks_for(2).is_empty(),
            "channel B was buffered, not read: its credit stays with us"
        );

        let n = now(reader.read_channel(b, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"for-b");
        assert_eq!(seen.acks_for(2), alloc::vec![5]);
    }
}

/// Nothing frees a slot but a close, a `Channel` having no `Drop`, so
/// whatever opened a channel has to close it on every way out.
mod slot_tests {
    use alloc::boxed::Box;
    use core::convert::Infallible;
    use core::future::Future;
    use core::pin::{pin, Pin};
    use core::task::{Context, Poll, Waker};

    use crate::base::channel::{Channel, ChannelId};
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        clse, cnxn_with, now, okay_with_budget, shell_frame, split_one_channel_delayed_ack,
        split_with_channel, wrte, Mock, MockError, NoAuth, SharedMock, FAILED_WRITES,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::{Error, ProtocolError};
    use crate::shell::v2::{self as shell_v2, CommandOutput, FrameId, Shell, WindowSize};
    use crate::sync::SyncSession;
    use crate::{cmd, logcat};

    use super::{Reader, Writer};

    /// A READY with no credit on it, which breaks a delayed-ACK channel.
    fn fault() -> Packet {
        Packet::new(Command::Ready, 42, 1, alloc::vec::Vec::new())
    }

    /// A delayed-ACK channel with `packets` dispatched into it.
    #[allow(clippy::type_complexity)]
    fn channel_with(
        packets: &[Packet],
    ) -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
        SharedMock,
    ) {
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(4096, packets);
        for _ in packets {
            now(reader.dispatch_one()).unwrap();
        }
        (reader, writer, ch, seen)
    }

    /// `collect` on a shell over `ch`, going through `writer`.
    fn collected(
        writer: &Writer<SharedMock>,
        ch: ChannelId,
    ) -> Result<CommandOutput, Error<MockError>> {
        let mut session = writer.clone();
        let channel = Channel {
            session: &mut session,
            id: ch,
        };
        let mut rx = [0u8; 64];
        now(Shell::new(channel, &mut rx).collect())
    }

    fn in_use(writer: &Writer<SharedMock>) -> usize {
        writer.shared.lock_channels().in_use()
    }

    #[test]
    fn collect_gives_the_slot_back_when_the_device_closes_with_no_exit_frame() {
        let stdout = shell_frame(FrameId::Stdout, b"so far");
        let (_reader, writer, ch, _seen) = channel_with(&[wrte(1, &stdout), clse(1)]);
        let output = collected(&writer, ch);
        assert!(matches!(output, Err(Error::ChannelClosed)), "{output:?}");
        assert_eq!(in_use(&writer), 0);
    }

    #[test]
    fn collect_gives_the_slot_back_on_a_fault() {
        let (_reader, writer, ch, _seen) = channel_with(&[fault()]);
        let output = collected(&writer, ch);
        assert!(
            matches!(
                output,
                Err(Error::Protocol(ProtocolError::ShortReadyPayload))
            ),
            "{output:?}"
        );
        assert_eq!(in_use(&writer), 0);
    }

    #[test]
    fn collect_gives_the_slot_back_on_a_protocol_error() {
        let (_reader, writer, ch, _seen) =
            channel_with(&[wrte(1, &shell_frame(FrameId::Exit, &[]))]);
        let output = collected(&writer, ch);
        assert!(
            matches!(
                output,
                Err(Error::Protocol(ProtocolError::ShortExitPayload))
            ),
            "{output:?}"
        );
        assert_eq!(in_use(&writer), 0);
    }

    #[test]
    fn collect_gives_the_slot_back_when_the_connection_ends() {
        let (mut reader, writer, ch, _seen) = channel_with(&[]);
        assert!(matches!(
            now(reader.dispatch_one()),
            Err(Error::UnexpectedEof)
        ));
        let output = collected(&writer, ch);
        assert!(matches!(output, Err(Error::Disconnected)), "{output:?}");
        assert_eq!(in_use(&writer), 0);
    }

    /// Without delayed ACK the frames are acknowledged as they land, so
    /// the CLSE is the one write left to fail.
    #[test]
    fn collect_keeps_a_finished_commands_output_when_its_close_fails() {
        for (kind, _) in FAILED_WRITES {
            let (mut reader, writer, ch) = split_with_channel(None);
            let seen = now(writer.shared.write_half.lock()).clone();
            let exit = shell_frame(FrameId::Exit, &[7]);
            seen.feed(&wrte(1, &shell_frame(FrameId::Stdout, b"out")));
            seen.feed(&wrte(1, &exit));
            for _ in 0..3 {
                now(reader.dispatch_one()).unwrap();
            }
            seen.fail_writes(kind);

            let output = collected(&writer, ch).unwrap();
            assert_eq!(output.stdout, b"out", "{kind:?}");
            assert_eq!(output.exit_code, 7, "{kind:?}");
        }
    }

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// A connection with nothing open yet, and the `run` that dispatches
    /// `answer` once a call has sent the OPEN it is for.
    #[allow(clippy::type_complexity)]
    fn dispatched(
        answer: &[Packet],
    ) -> (
        Pin<Box<impl Future<Output = Result<Infallible, Error<MockError>>>>>,
        Writer<SharedMock>,
    ) {
        let mut mock = Mock::new();
        mock.feed(&cnxn_with("shell_v2,delayed_ack"));
        for pkt in answer {
            mock.feed(pkt);
        }
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Raw(b"host::features=shell_v2,delayed_ack"),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (reader, writer) = conn.split().unwrap();
        seen.parks_when_drained();
        (Box::pin(reader.run()), writer)
    }

    /// Poll `fut` and `run` in turn until `fut` finishes.
    fn driven<R: Future + ?Sized, F: Future>(run: &mut Pin<Box<R>>, fut: F) -> F::Output {
        let mut fut = pin!(fut);
        for _ in 0..64 {
            if let Poll::Ready(output) = poll_once(fut.as_mut()) {
                return output;
            }
            assert!(poll_once(run.as_mut()).is_pending(), "run ended");
        }
        panic!("the call never finished");
    }

    type OneShot = for<'a> fn(
        &'a mut Writer<SharedMock>,
        &'a mut [u8],
    )
        -> Pin<Box<dyn Future<Output = Result<(), Error<MockError>>> + 'a>>;

    /// The calls that close a command's stdin for it and collect what it
    /// wrote.
    const ONE_SHOTS: [OneShot; 3] = [
        |writer, rx| Box::pin(async { shell_v2::exec(writer, "x", rx).await.map(drop) }),
        |writer, rx| Box::pin(async { cmd::exec(writer, &["x"], rx).await.map(drop) }),
        |writer, rx| Box::pin(async { logcat::exec_text(writer, &["-d"], rx).await.map(drop) }),
    ];

    /// The fault closes the channel for the first write on it, which
    /// leaves the device nothing to do with the close.
    #[test]
    fn a_one_shot_gives_the_slot_back_when_close_stdin_fails() {
        for one_shot in ONE_SHOTS {
            let (mut run, mut writer) = dispatched(&[okay_with_budget(1, 4096), fault()]);
            let mut rx = [0u8; 64];
            let err = driven(&mut run, one_shot(&mut writer, &mut rx)).unwrap_err();
            assert!(
                matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
                "got {err:?}"
            );
            assert_eq!(in_use(&writer), 0);
        }
    }

    #[test]
    fn open_interactive_gives_the_slot_back_when_the_window_size_fails() {
        let (mut run, mut writer) = dispatched(&[okay_with_budget(1, 4096), fault()]);
        let mut rx = [0u8; 64];
        let size = Some(WindowSize { rows: 24, cols: 80 });
        let opened = shell_v2::open_interactive(&mut writer, "", None, size, &mut rx);
        let err = driven(&mut run, async { opened.await.map(drop) }).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
            "got {err:?}"
        );
        assert_eq!(in_use(&writer), 0);
    }

    /// `quit` on a sync session over `ch`, going through `writer`.
    fn quit(writer: &Writer<SharedMock>, ch: ChannelId) -> Result<(), Error<MockError>> {
        let mut session = writer.clone();
        let channel = Channel {
            session: &mut session,
            id: ch,
        };
        let mut buf = [0u8; 64];
        now(SyncSession::new(channel, &mut buf).quit())
    }

    #[test]
    fn quit_on_a_channel_the_device_closed_is_no_failure() {
        let (_reader, writer, ch, _seen) = channel_with(&[clse(1)]);
        quit(&writer, ch).unwrap();
        assert_eq!(in_use(&writer), 0);
    }

    #[test]
    fn quit_on_a_channel_a_fault_closed_fails_with_the_fault() {
        let (_reader, writer, ch, _seen) = channel_with(&[fault()]);
        let err = quit(&writer, ch).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
            "got {err:?}"
        );
        assert_eq!(in_use(&writer), 0);
    }
}

/// What a write to a channel the device closed comes to on a `Writer`.
mod closed_channel_tests {
    use crate::base::channel::Channel;
    use crate::base::mock::{clse, now, split_one_channel_delayed_ack, sync_fail, wrte};
    use crate::base::protocol::command::Command;
    use crate::error::{Error, SyncError};
    use crate::sync::{FileMode, SyncSession};

    #[test]
    fn a_write_to_a_channel_the_device_closed_fails_and_sends_nothing() {
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(4096, &[clse(1)]);
        now(reader.dispatch_one()).unwrap();
        let err = now(writer.write_channel(ch, b"nobody reads this")).unwrap_err();
        assert!(matches!(err, Error::ChannelClosed), "got {err:?}");
        assert!(!seen.sent().iter().any(|(cmd, ..)| *cmd == Command::Write));
    }

    /// As `handle_send_file` goes: the `FAIL`, and nothing closed until
    /// the host's `DONE`.
    #[test]
    fn a_failed_push_gets_the_devices_text() {
        const TEXT: &[u8] = b"couldn't create file: Read-only file system";
        let fail = sync_fail(TEXT);
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(4096, &[wrte(1, &fail)]);
        now(reader.dispatch_one()).unwrap();

        let mut session = writer.clone();
        let channel = Channel {
            session: &mut session,
            id: ch,
        };
        let mut buf = [0u8; 256];
        let mut sync = SyncSession::new(channel, &mut buf);
        let err = now(sync.send("/x", FileMode(0o644), 0, b"data")).unwrap_err();
        assert!(
            matches!(&err, Error::Sync(SyncError::Failed(text)) if text == TEXT),
            "got {err:?}"
        );

        seen.feed(&clse(1));
        now(reader.dispatch_one()).unwrap();
        now(sync.quit()).unwrap();
        assert_eq!(writer.shared.lock_channels().in_use(), 0);
    }
}
