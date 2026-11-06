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
    let inc = reader
        .try_accept_incoming()
        .unwrap()
        .expect("the OPEN was queued");

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
    assert!(reader.try_accept_incoming().unwrap().is_none());
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

/// The slot is reserved by then, and the withdrawal closes it.
#[test]
fn a_withdrawal_while_accept_waits_for_the_write_half_sends_no_ready() {
    use core::task::{Context, Waker};

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
    let (mut reader, writer) = conn.split().unwrap();
    seen.feed(&Packet::new(Command::Open, 90, 0, b"tcp:90\0".to_vec()));
    let inc = now(reader.accept_incoming()).unwrap();

    let busy = now(writer.shared.write_half.lock());
    let mut accept = pin!(inc.accept());
    let waiting = accept
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    assert!(waiting.is_pending());
    seen.feed(&withdraw(90));
    now(reader.dispatch_one()).unwrap();
    drop(busy);

    let err = now(accept).unwrap_err();
    assert!(matches!(err, Error::ChannelClosed), "got {err:?}");
    assert!(
        !seen
            .sent()
            .iter()
            .any(|(cmd, _, arg1, _)| *cmd == Command::Ready && *arg1 == 90),
        "READY must not answer a withdrawn OPEN"
    );
    assert_eq!(writer.shared.lock_channels().in_use(), 0);
    assert!(reader.try_accept_incoming().unwrap().is_none());
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
    let held_a = reader.try_accept_incoming().unwrap().unwrap();
    seen.feed(&open_pkt(61, b"tcp:61\0"));
    pump(&mut reader);
    let held_b = reader.try_accept_incoming().unwrap().unwrap();
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
        reader.try_accept_incoming().unwrap().is_none(),
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
    let inc = reader.try_accept_incoming().unwrap().unwrap();
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
    // ... and the opener gets the fault too, instead of waiting on.
    let err = now(open).unwrap_err();
    assert!(
        matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
        "opener: got {err:?}"
    );
    let (cmd, arg0, arg1, _) = seen.sent().last().unwrap().clone();
    assert_eq!((cmd, arg0, arg1), (Command::Close, 2, 43));
}

#[test]
fn a_write_before_its_ready_fails_a_reader_open() {
    use crate::error::ProtocolError;

    let mut mock = Mock::new();
    mock.feed(&crate::base::mock::cnxn())
        .feed(&wrte(1, b"early"))
        .feed(&okay(1));
    let seen = SharedMock::new(mock);
    let conn = now(Connection::connect(
        seen.clone(),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();

    let err = now(reader.open_channel(b"shell:\0")).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol(ProtocolError::UnexpectedCommand(Command::Write))
        ),
        "got {err:?}"
    );
    let (cmd, local, remote, _) = seen.sent().last().unwrap().clone();
    assert_eq!((cmd, local, remote), (Command::Close, 1, 42));
}

#[test]
fn a_write_before_its_ready_fails_a_writer_open_on_a_reader_driven_connection() {
    use crate::error::ProtocolError;
    use core::task::{Context, Waker};

    let (mut reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(
        64,
        &[
            Packet::new(Command::Write, 43, 2, b"early".to_vec()),
            Packet::new(Command::Ready, 43, 2, 64u32.to_le_bytes().to_vec()),
        ],
    );
    let mut open = pin!(writer.open_channel(b"svc:\0"));
    assert!(open
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());

    let broken = |err: &Error<_>| {
        matches!(
            err,
            Error::Protocol(ProtocolError::UnexpectedCommand(Command::Write))
        )
    };
    let mut buf = [0u8; 8];
    let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
    assert!(broken(&err), "reader: got {err:?}");
    let err = now(open).unwrap_err();
    assert!(broken(&err), "opener: got {err:?}");
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

/// The next read gets the bytes and sends the OKAY.
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

/// Returning zero for an empty packet would tell the caller nothing.
#[test]
fn a_reader_reads_past_a_zero_length_write() {
    let (mut reader, _writer, ch, _seen) =
        crate::base::mock::split_one_channel_delayed_ack(64, &[wrte(1, b""), wrte(1, b"after it")]);
    let mut buf = [0u8; 16];
    let n = now(reader.read_channel(ch, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"after it");
}

/// The device sends nothing more on this channel until the OKAY comes.
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

/// The packet a read waits for goes through the slot whole, and the cap
/// never drops below a packet.
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
    // The opener was dropped between the fault and this: its slot is
    // free, but the device still holds the channel open.
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

/// The abandoned write does not affect bytes the device had already
/// delivered. Only the next read fails.
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

/// The failure is the connection's: the bytes did arrive.
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

/// Writes fail with these kinds once the device is gone. No stream is
/// left to fall out of step with, so reads still get what it sent
/// before that, buffered or on the wire.
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

/// With any other failure the device may still be there, and would read
/// whatever comes next as the rest of the packet.
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

/// Without delayed ACK the OKAY goes out at dispatch, with the packet
/// the read waits for still in the slot.
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

/// If the bytes left the buffer before the OKAY was written, dropping
/// the call would lose them. A desync no longer stops the next read, so
/// it would skip the gap and report nothing.
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

/// An OKAY lets the device send as much again, and `run` can receive
/// that while the write is still finishing. A read that took those bytes
/// along would leave their OKAY unsent, and the credit lost for good.
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

/// Read `ch` with the OKAY for `packets[0]` still going out. A second
/// read takes those bytes and `packets[1]` lands in their place, so the
/// first read returns `packets[1]`, which owes an OKAY of its own.
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

/// Under delayed ACK, with the buffer empty, no later read would
/// acknowledge those bytes, and their credit would be lost for good.
#[test]
fn a_read_overtaken_during_its_okay_owes_what_it_takes_instead() {
    let (mut reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(64, &[]);
    read_overtaken_during_its_okay(&mut reader, &writer, ch, &seen, [b"hello", b" world"]);
    assert_eq!(seen.acks_for(1), [5, 6], "credit for every byte read");
}

/// Without delayed ACK a packet that reaches the watermark holds back
/// its OKAY until a read. The device waits for that OKAY before it
/// sends another packet, so without it the channel stops.
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

/// A read that tried to send the OKAY would never finish: every write
/// stalls here.
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

/// What a closed channel still holds owes no OKAY.
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

/// The OKAY or CLSE a received packet owes the device outlives the call
/// that took the packet in. A call dropped behind a busy writer leaves
/// it to go out ahead of whatever comes next, oldest first.
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

    /// The device's READY to an OPEN dropped before the answer.
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

    /// A READY without its credit breaks channel 1, while the device
    /// still treats its end as open.
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

    /// `dispatch_one` waits as long as a packet takes, and a device owed
    /// an OKAY may have no reason to send one. The read here hits the
    /// end of the mock, and the debt must be out by then.
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

    /// The opener is dropped after the read that received its packets,
    /// so the CLSE is owed after the OKAY for the same channel. Sending
    /// the newest first would close the channel before its OKAY.
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

    /// Nothing more is received until the list is sent, so a call
    /// dropped again and again adds nothing, even with more packets
    /// waiting.
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

    /// Only the wait for the write half is safe to drop. Past it the
    /// packet is on its way out, and a drop abandons it.
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

    /// The debt cannot be paid, and must not keep back the packets
    /// behind it.
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

    /// `run` refuses requests nobody listens for before every receive.
    /// The refusal fails here, which consumes the request, and stopping
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

    /// The call that received the OPEN past the cap does not fail with
    /// the refusal: the packets behind it are still to be read.
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

    /// The same for an OPEN that a cancelled refusal left past the cap.
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

    /// Reception goes on after the device is gone, to get what it sent
    /// before that, which may be more OPENs than the queue has room
    /// for. Each refusal fails. If a refused OPEN went back to the
    /// queue, each would sit one past the cap and keep its destination.
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

    /// The call fails either way. With the device gone nothing is left
    /// to refuse, so the request is consumed. Any other failure puts it
    /// back for another verdict.
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

    /// With no slot free an accept is a refusal, and behaves the same.
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

    /// With the device gone nobody can use the channel, so the request
    /// is consumed. A listener that carries on waits for the end of the
    /// connection, rather than get the same request for ever. After any
    /// other failure the request stays queued and the next accept fails
    /// with the desync.
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

    /// The same on a `Reader`: only with the request out of the way
    /// does `accept_incoming` reach the packets the device had already
    /// sent, and the end of the stream after them.
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

/// Callers are promised that dropping the wait for the write half is
/// safe, so the wait writes nothing, whatever is owed. They then write
/// only their own packet, and what is owed stays for a call that would
/// write anyway.
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

    /// With no slot free the accept is a refusal, and behaves the same.
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

    /// Every write stalls here. The device closes the channel while the
    /// read waits for the write half, which leaves no OKAY owed and
    /// nothing for the read to write.
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

    /// The read stalls in its own OKAY, not in what is owed. That write
    /// has been polled, so dropping the read abandons the packet. The
    /// read keeps what it promised: the bytes stay readable.
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
    use crate::base::mock::{
        abandon, now, split_one_channel_delayed_ack, split_with_channel, wrte,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::Error;

    fn open_pkt(remote_id: u32, credit: u32, dest: &[u8]) -> Packet {
        Packet::new(Command::Open, remote_id, credit, dest.to_vec())
    }

    /// A request taken here could only fail its verdict with the desync
    /// and go back to the queue, to be taken again.
    #[test]
    fn try_accept_incoming_fails_once_the_connection_is_desynchronized() {
        let (mut reader, writer, ch) = split_with_channel(Some(1));
        let seen = now(writer.shared.write_half.lock()).clone();
        seen.feed(&open_pkt(77, 0, b"tcp:80\0"));
        now(reader.dispatch_one()).unwrap();
        now(reader.dispatch_one()).unwrap();
        abandon(writer.write_channel(ch, b"payload-that-never-made-it"));
        let taken = reader.try_accept_incoming().map(|_| ());
        assert!(matches!(taken, Err(Error::Desynchronized)), "got {taken:?}");
    }

    #[test]
    fn a_request_queued_before_a_clean_end_is_still_handed_out() {
        let opened = [open_pkt(77, 0, b"tcp:80\0")];
        let (mut reader, _writer, _ch, _seen) = split_one_channel_delayed_ack(0, &opened);
        now(reader.dispatch_one()).unwrap();
        let end = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(end, Error::UnexpectedEof), "got {end:?}");

        let incoming = reader.try_accept_incoming().unwrap();
        now(incoming.expect("queued before the end").reject()).unwrap();
        let next = reader.try_accept_incoming().map(|_| ());
        assert!(matches!(next, Err(Error::Disconnected)), "got {next:?}");
    }

    #[test]
    fn try_accept_incoming_with_nothing_queued_is_none() {
        let (mut reader, _writer, _ch, _seen) = split_one_channel_delayed_ack(0, &[]);
        assert!(reader.try_accept_incoming().unwrap().is_none());
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

/// A reader-driven connection ends in a receive that some call happens
/// to be making. That call gets the failure, and everyone else waiting
/// on the connection must be told too, or they wait for ever.
mod end_tests {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, Ordering};
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

    /// Two channels without delayed ACK. `a` has one WRTE out, so the
    /// next write on it waits for its OKAY, and a read of `a` waits for
    /// a packet.
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

    /// Each call that waits for the device, polled until it parks.
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

    /// The error kinds of a dropped connection, which `ErrorKind` can
    /// tell from a timeout.
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

    /// Only the caller who set a read timeout can tell it from another
    /// failure: on unix `SO_RCVTIMEO` comes back as `WouldBlock`, which
    /// is `ErrorKind::Other` here. A timeout says nothing about the
    /// connection, so nothing ends and the waiters stay parked.
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

    /// A packet with a wrong checksum was read whole, so the stream
    /// keeps its place. The packet is lost, as it always was, and the
    /// next one is read.
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

    /// The stream ends while a stalled writer holds the write half. The
    /// read gets the bytes that arrived and sends no OKAY: the device is
    /// gone.
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

    /// The same with the OKAY stalled in the transport. Abandoning it
    /// keeps the bytes readable. It leaves half a packet, so writes fail
    /// with the desync, but calls waiting on the device still report the
    /// end of the connection.
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
        let err = now(writer.close_channel(ch)).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "close: {err:?}");
    }

    /// The device closed the channel before the stream ended. The OKAY
    /// abandoned after that does not hide the close.
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

    /// No verdict can get out now, so the request would only come back,
    /// for ever, to a listener that carries on.
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

    /// No OKAY can reach the device by the time the write half comes
    /// free, so the read writes nothing that could stall.
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

    /// Once the stream has ended no call reads the transport again, and
    /// none writes a packet that could only wait for an answer.
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

    struct Woken(AtomicBool);

    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    fn parked_for_credit<'a>(
        writer: &'a Writer<SharedMock>,
        a: ChannelId,
    ) -> (Waiter<'a>, Arc<Woken>) {
        let woken = Arc::new(Woken(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&woken));
        let mut parked: Waiter<'a> =
            Box::pin(async move { ("write", writer.write_channel(a, b"two").await.err()) });
        let first = parked.as_mut().poll(&mut Context::from_waker(&waker));
        assert!(first.is_pending());
        assert!(writer.waits_for_credit(a));
        (parked, woken)
    }

    fn assert_woken_to_disconnected(mut parked: Waiter<'_>, woken: &Woken) {
        assert!(woken.0.load(Ordering::Relaxed), "the parked write slept on");
        let Poll::Ready((_, err)) = poll_once(parked.as_mut()) else {
            panic!("the parked write is still waiting for credit");
        };
        assert!(matches!(err, Some(Error::Disconnected)), "got {err:?}");
    }

    #[test]
    fn a_write_parked_for_credit_ends_with_run_after_another_finds_the_device_gone() {
        let (reader, writer, a, b, seen) = two_channels();
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());
        let (parked, woken) = parked_for_credit(&writer, a);

        seen.fail_writes(ErrorKind::BrokenPipe);
        let err = now(writer.write_channel(b, b"x")).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        assert_woken_to_disconnected(parked, &woken);
    }

    /// The receive under way is a read of the other channel, and then
    /// the `dispatch_one` that `Writer::waits_for_credit` calls for.
    #[test]
    fn a_write_parked_for_credit_ends_with_a_receive_after_another_finds_the_device_gone() {
        for dispatch_one in [false, true] {
            let (mut reader, writer, a, b, seen) = two_channels();
            let (parked, woken) = parked_for_credit(&writer, a);
            let mut buf = [0u8; 8];
            let mut receive: Pin<Box<dyn Future<Output = Result<(), Error<MockError>>> + '_>> =
                if dispatch_one {
                    Box::pin(reader.dispatch_one())
                } else {
                    Box::pin(async { reader.read_channel(b, &mut buf).await.map(drop) })
                };
            assert!(poll_once(receive.as_mut()).is_pending());

            seen.fail_writes(ErrorKind::BrokenPipe);
            let err = now(writer.write_channel(b, b"x")).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "got {err:?}");
            seen.hang_up();
            let end = now(receive).unwrap_err();
            assert!(matches!(end, Error::UnexpectedEof), "got {end:?}");
            assert_woken_to_disconnected(parked, &woken);
        }
    }
}

/// A write abandoned mid-packet ends the connection for good, and the
/// read side does not write, so it cannot find that out by itself.
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

    /// One channel with credit and a transport that stalls every write,
    /// so that any write can be abandoned mid-packet.
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

        // The desync ended it, and later calls report the same error.
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

    /// `run` may be waiting on a read it must not drop, so the next
    /// packet is its first chance to stop.
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

    /// A desync from before the read ends its loop on the way in too,
    /// without asking the transport for more.
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

/// What becomes owed while a call waits for a packet must be sent by
/// that call: reads leave it alone, and the device may send nothing
/// until it arrives.
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

    /// An OPEN whose READY was received but not yet seen by the opener.
    /// Dropping the opener leaves a CLSE owed, which only `run` or a
    /// read can send.
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

    /// The read must finish first, which takes as long as the device
    /// does, the same as after an abandoned write.
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

    /// An opener dropped after the stream ended leaves a CLSE owed. It
    /// cannot reach the device, so the read must get the bytes that
    /// arrived without the write half, which stays held here.
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
    /// cannot answer a packet it has not received, so a read here would
    /// wait on the very write it blocks. On USB the header would be out
    /// and the payload never sent. A WRTE for another channel would make
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

    /// An abandoned transfer stops counting, or the writers left would
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

    /// Buffered bytes keep their credit until they are read.
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

    /// `run` would refuse this OPEN with no listener alive, but
    /// `accept_incoming` needs no listener.
    #[test]
    fn an_incoming_open_stays_queued_for_accept() {
        let (mut reader, _writer, _ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.feed(&Packet::new(Command::Open, 77, 4096, b"tcp:80\0".to_vec()));

        now(reader.dispatch_one()).unwrap();
        assert!(closes(&seen).is_empty(), "the OPEN was refused");
        let incoming = reader
            .try_accept_incoming()
            .unwrap()
            .expect("the OPEN is queued");
        assert_eq!(incoming.destination(), b"tcp:80\0");
    }

    /// A READY without its credit concerns channel 1 alone, so the call
    /// that happened to take the packet carries on.
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

    /// As in `read_channel`: an OPEN that a cancelled refusal left past
    /// the cap is refused before another packet is received.
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

/// A `Channel` has no `Drop`, so only a close frees a slot, and
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
            assert_eq!(in_use(&writer), 0, "{kind:?}");
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

    /// The fault closes the channel before the first write on it, so
    /// the device takes no part in the close.
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

/// How a `Writer` handles a write to a channel the device closed.
mod closed_channel_tests {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Waker};

    use crate::base::channel::{Channel, ChannelId};
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        clse, cnxn_with, now, okay, okay_with_budget, split_one_channel_delayed_ack, sync_fail,
        wrte, Mock, MockError, NoAuth, SharedMock,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::{Error, SyncError};
    use crate::sync::{FileMode, SyncFlags, SyncSession};

    use super::{Reader, Writer};

    #[test]
    fn a_write_to_a_channel_the_device_closed_fails_and_sends_nothing() {
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(4096, &[clse(1)]);
        now(reader.dispatch_one()).unwrap();
        let err = now(writer.write_channel(ch, b"nobody reads this")).unwrap_err();
        assert!(matches!(err, Error::ChannelClosed), "got {err:?}");
        assert!(!seen.sent().iter().any(|(cmd, ..)| *cmd == Command::Write));
    }

    /// This follows `handle_send_file`: the `FAIL` comes first, and
    /// nothing is closed until the host's `DONE`.
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

    const REFUSAL: &[u8] = b"path too long";

    #[allow(clippy::type_complexity)]
    fn sync_device(
        credit: Option<u32>,
    ) -> (
        Reader<SharedMock, SharedMock>,
        Writer<SharedMock>,
        ChannelId,
        SharedMock,
    ) {
        let mut mock = Mock::new();
        let host: &[u8] = match credit {
            None => {
                mock.feed(&cnxn_with("sendrecv_v2")).feed(&okay(1));
                b"host::features="
            }
            Some(credit) => {
                mock.feed(&cnxn_with("sendrecv_v2,delayed_ack"))
                    .feed(&okay_with_budget(1, credit));
                b"host::features=delayed_ack"
            }
        };
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Raw(host),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"sync:\0")).unwrap();
        (reader, writer, ch, seen)
    }

    fn answered<F: Future>(
        push: F,
        reader: &mut Reader<SharedMock, SharedMock>,
        seen: &SharedMock,
        answer: &[Packet],
    ) -> F::Output {
        let mut push = pin!(push);
        for pkt in answer {
            let waiting = push.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            assert!(waiting.is_pending(), "the push did not wait for the device");
            seen.feed(pkt);
            now(reader.dispatch_one()).unwrap();
        }
        now(push)
    }

    fn push_answered_with(credit: Option<u32>, v2: bool, answer: &[Packet]) -> Error<MockError> {
        let (mut reader, writer, ch, seen) = sync_device(credit);
        let mut session = writer.clone();
        let channel = Channel {
            session: &mut session,
            id: ch,
        };
        let mut buf = [0u8; 256];
        let mut sync = SyncSession::new(channel, &mut buf);
        let data = [0x5a; 256];
        let mode = FileMode(0o644);
        let pushed = if v2 {
            let push = sync.send_v2("/x", mode, 0, SyncFlags::NONE, &data);
            answered(push, &mut reader, &seen, answer)
        } else {
            answered(sync.send("/x", mode, 0, &data), &mut reader, &seen, answer)
        };
        now(sync.quit()).unwrap();
        assert_eq!(writer.shared.lock_channels().in_use(), 0);
        pushed.unwrap_err()
    }

    /// This follows `handle_sync_command` on a path over 1024 bytes: the
    /// `FAIL` and the CLSE come before the device reads anything past
    /// the request. The 256 bytes of data wait for the OKAY of the
    /// request, or with credit for 64 bytes run out of it part way, and
    /// the device's answer is dispatched while they wait.
    #[test]
    fn a_push_the_device_fails_before_its_data_gets_the_devices_text() {
        let fail = sync_fail(REFUSAL);
        for credit in [None, Some(64)] {
            for v2 in [false, true] {
                let err = push_answered_with(credit, v2, &[wrte(1, &fail), clse(1)]);
                assert!(
                    matches!(&err, Error::Sync(SyncError::Failed(text)) if text == REFUSAL),
                    "credit {credit:?}, v2 {v2}: got {err:?}"
                );
            }
        }
    }

    /// This follows `handle_send_link` on a `symlink` that fails: the
    /// `FAIL` and the CLSE come once the device has read the data,
    /// while `DONE` waits for the OKAY of the data.
    #[test]
    fn a_push_the_device_fails_before_done_gets_the_devices_text() {
        let text = b"symlink failed: Read-only file system";
        let answer = [okay(1), okay(1), wrte(1, &sync_fail(text)), clse(1)];
        for v2 in [false, true] {
            let err = push_answered_with(None, v2, &answer);
            assert!(
                matches!(&err, Error::Sync(SyncError::Failed(got)) if got == text),
                "v2 {v2}: got {err:?}"
            );
        }
    }

    #[test]
    fn a_push_the_device_closes_with_no_fail_is_channel_closed() {
        for credit in [None, Some(64)] {
            for v2 in [false, true] {
                let err = push_answered_with(credit, v2, &[clse(1)]);
                assert!(
                    matches!(err, Error::ChannelClosed),
                    "credit {credit:?}, v2 {v2}: got {err:?}"
                );
            }
        }
    }
}

/// A close frees its slot first, and its CLSE is owed like any other
/// packet.
mod close_tests {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, Waker};
    use embedded_io::ErrorKind;

    use crate::base::channel::{Channel, ChannelId};
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        abandon, cnxn, now, okay, shell_frame, split_one_channel_delayed_ack,
        split_two_channels_delayed_ack, wrte, Mock, MockError, NoAuth, SharedMock, FAILED_WRITES,
    };
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;
    use crate::error::Error;
    use crate::shell::v2::{FrameId, Shell};

    use super::Writer;

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// Drop `fut` where its first poll leaves it, as a timeout would.
    fn dropped_parked<F: Future>(fut: F) {
        assert!(poll_once(Box::pin(fut).as_mut()).is_pending());
    }

    fn in_use(writer: &Writer<SharedMock>) -> usize {
        writer.shared.lock_channels().in_use()
    }

    /// CLSEs the halves sent, as (our end, the device's end).
    fn closes(seen: &SharedMock) -> Vec<(u32, u32)> {
        seen.sent()
            .into_iter()
            .filter(|(cmd, ..)| *cmd == Command::Close)
            .map(|(_, arg0, arg1, _)| (arg0, arg1))
            .collect()
    }

    struct Woken(AtomicBool);

    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    /// A writer is parked for credit on a channel that has none when
    /// the close fails. The slot comes back and the writer is woken,
    /// which is all a close promises if its CLSE fails.
    #[test]
    fn a_close_that_fails_gives_the_slot_back_and_wakes_parked_writers() {
        for (kind, left) in FAILED_WRITES {
            let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(0, &[]);
            let woken = Arc::new(Woken(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&woken));
            let mut parked = Box::pin(writer.write_channel(ch, b"x"));
            assert!(parked
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());

            seen.fail_writes(kind);
            let closed = now(writer.close_channel(ch));
            if left == 0 {
                closed.unwrap();
            } else {
                let err = closed.unwrap_err();
                assert!(
                    matches!(&err, Error::Io(e) if embedded_io::Error::kind(e) == kind),
                    "{kind:?}: {err:?}"
                );
            }

            assert_eq!(in_use(&writer), 0, "{kind:?}");
            assert!(woken.0.load(Ordering::Relaxed), "{kind:?}");
            assert!(matches!(
                poll_once(parked.as_mut()),
                Poll::Ready(Err(Error::ChannelClosed))
            ));
        }
    }

    #[test]
    fn a_close_dropped_behind_a_busy_writer_gives_the_slot_back_and_owes_its_clse() {
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        let busy = now(writer.shared.write_half.lock());
        dropped_parked(writer.close_channel(ch));
        assert_eq!(in_use(&writer), 0);
        assert!(closes(&seen).is_empty());
        drop(busy);

        let _ = now(reader.dispatch_one());
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    /// A receive in flight gives way to what is owed, so once the close
    /// is dropped `run` sends the CLSE.
    #[test]
    fn a_close_dropped_with_run_parked_gets_its_clse_out() {
        let (reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.parks_when_drained();
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        let busy = now(writer.shared.write_half.lock());
        dropped_parked(writer.close_channel(ch));
        assert!(poll_once(run.as_mut()).is_pending());
        assert!(closes(&seen).is_empty());
        drop(busy);

        assert!(poll_once(run.as_mut()).is_pending());
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    /// With the stream over the CLSE is called off, so the close does
    /// not wait for the write half, which stays held here.
    #[test]
    fn a_close_after_the_end_of_the_stream_leaves_the_write_half_alone() {
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        let end = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(end, Error::UnexpectedEof), "got {end:?}");
        let sent = seen.sent().len();

        let busy = now(writer.shared.write_half.lock());
        now(writer.close_channel(ch)).unwrap();
        assert_eq!(in_use(&writer), 0);
        drop(busy);
        assert_eq!(seen.sent().len(), sent, "nobody is left to hear it");
    }

    #[test]
    fn a_close_on_the_reader_after_the_end_leaves_the_write_half_alone() {
        let (mut reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        let end = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(end, Error::UnexpectedEof), "got {end:?}");

        let busy = now(writer.shared.write_half.lock());
        now(reader.close_channel(ch)).unwrap();
        assert_eq!(in_use(&writer), 0);
        drop(busy);
        assert!(closes(&seen).is_empty());
    }

    /// Dropping the `Reader` says nothing about the device, and at
    /// shutdown a close may be the only way left to tell it.
    #[test]
    fn a_close_after_the_reader_went_puts_its_clse_on_the_wire() {
        let (reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        drop(reader);
        now(writer.close_channel(ch)).unwrap();
        assert_eq!(in_use(&writer), 0);
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    #[test]
    fn a_close_after_the_end_goes_out_with_a_write_that_goes_anyway() {
        let (mut reader, a, b, seen) = split_two_channels_delayed_ack(&[]);
        let end = now(reader.dispatch_one()).unwrap_err();
        assert!(matches!(end, Error::UnexpectedEof), "got {end:?}");

        now(reader.close_channel(a)).unwrap();
        assert!(closes(&seen).is_empty());

        let writer = Writer::new(Arc::clone(&reader.shared));
        now(writer.write_channel(b, b"x")).unwrap();
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    #[test]
    fn a_close_behind_a_stalled_writer_outlasts_the_reader() {
        let (reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        let busy = now(writer.shared.write_half.lock());
        let mut close = Box::pin(writer.close_channel(ch));
        assert!(poll_once(close.as_mut()).is_pending());

        drop(reader);
        assert!(poll_once(close.as_mut()).is_pending());
        assert!(closes(&seen).is_empty());

        drop(busy);
        assert!(matches!(poll_once(close.as_mut()), Poll::Ready(Ok(()))));
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    /// With the `Reader` gone nothing receives, so the next call that
    /// writes sends the CLSE.
    #[test]
    fn a_close_dropped_past_the_reader_still_owes_its_clse() {
        let (reader, a, b, seen) = split_two_channels_delayed_ack(&[]);
        let writer = Writer::new(Arc::clone(&reader.shared));
        let busy = now(writer.shared.write_half.lock());
        let mut close = Box::pin(writer.close_channel(a));
        assert!(poll_once(close.as_mut()).is_pending());

        drop(reader);
        assert!(poll_once(close.as_mut()).is_pending());
        drop(close);
        assert_eq!(writer.shared.lock_owed().len(), 1);
        drop(busy);

        now(writer.write_channel(b, b"x")).unwrap();
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    /// With the CLSE stalled in the transport, only the end of the
    /// stream abandons that packet.
    #[test]
    fn a_close_stalled_in_its_clse_outlasts_the_reader() {
        let (reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.stall_writes();
        let mut close = Box::pin(writer.close_channel(ch));
        assert!(poll_once(close.as_mut()).is_pending());

        drop(reader);
        assert!(poll_once(close.as_mut()).is_pending());
        assert!(writer.shared.desync.check::<Infallible>().is_ok());
    }

    /// `run` with a read under way that cannot be dropped, which lets a
    /// packet, or the end of the stream, arrive after a close.
    #[allow(clippy::type_complexity)]
    fn read_under_way() -> (
        Pin<Box<impl Future<Output = Result<Infallible, Error<MockError>>>>>,
        Writer<SharedMock>,
        ChannelId,
        SharedMock,
    ) {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1)).loses_cancelled_reads();
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
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());
        (run, writer, ch, seen)
    }

    #[test]
    fn a_close_behind_a_stalled_writer_ends_with_a_read_that_meets_the_end() {
        let (mut run, writer, ch, seen) = read_under_way();
        let busy = now(writer.shared.write_half.lock());
        let mut close = Box::pin(writer.close_channel(ch));
        assert!(poll_once(close.as_mut()).is_pending());
        assert!(poll_once(run.as_mut()).is_pending());

        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        assert!(matches!(poll_once(close.as_mut()), Poll::Ready(Ok(()))));
        drop(busy);
    }

    /// Abandoning the CLSE leaves half a packet, which says nothing
    /// about how the stream ended, so the close reports no failure.
    #[test]
    fn a_close_stalled_in_its_clse_ends_with_a_read_that_meets_the_end() {
        let (mut run, writer, ch, seen) = read_under_way();
        seen.stall_writes();
        let mut close = Box::pin(writer.close_channel(ch));
        assert!(poll_once(close.as_mut()).is_pending());

        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        assert!(matches!(poll_once(close.as_mut()), Poll::Ready(Ok(()))));
        assert!(writer.shared.desync.check::<Infallible>().is_err());
    }

    /// What `collect` read comes back once the stream ends, rather than
    /// wait in the close for a writer that may never let go.
    #[test]
    fn a_finished_commands_output_gets_past_a_stalled_writer_at_the_end() {
        let (mut run, writer, ch, seen) = read_under_way();
        seen.feed(&wrte(1, &shell_frame(FrameId::Stdout, b"out")));
        seen.feed(&wrte(1, &shell_frame(FrameId::Exit, &[7])));
        assert!(poll_once(run.as_mut()).is_pending());

        let busy = now(writer.shared.write_half.lock());
        let mut session = writer.clone();
        let channel = Channel {
            session: &mut session,
            id: ch,
        };
        let mut rx = [0u8; 64];
        let mut collect = Box::pin(Shell::new(channel, &mut rx).collect());
        assert!(poll_once(collect.as_mut()).is_pending());

        seen.hang_up();
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(Error::UnexpectedEof))
        ));
        let Poll::Ready(output) = poll_once(collect.as_mut()) else {
            panic!("the output stayed behind the close");
        };
        let output = output.unwrap();
        assert_eq!(
            (output.stdout.as_slice(), output.exit_code),
            (&b"out"[..], 7)
        );
        drop(busy);
    }

    #[test]
    fn a_close_after_a_desync_fails_with_it() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.stall_writes();
        abandon(writer.write_channel(ch, b"x"));

        let err = now(writer.close_channel(ch)).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
        assert_eq!(in_use(&writer), 1);
    }

    /// The desync happens with the close parked, and another call takes
    /// the write half next, so the close cannot find out by writing.
    /// Its CLSE will never go out, and it must not report that it did.
    #[test]
    fn a_close_parked_when_a_write_is_given_up_on_fails_with_the_desync() {
        let (reader, a, b, seen) = split_two_channels_delayed_ack(&[]);
        let writer = Writer::new(Arc::clone(&reader.shared));
        seen.stall_writes();
        let mut write = Box::pin(writer.write_channel(a, b"x"));
        assert!(poll_once(write.as_mut()).is_pending());
        let mut close = Box::pin(writer.close_channel(b));
        assert!(poll_once(close.as_mut()).is_pending());

        drop(write);
        let busy = now(writer.shared.write_half.lock());
        assert!(matches!(
            poll_once(close.as_mut()),
            Poll::Ready(Err(Error::Desynchronized))
        ));
        drop(busy);
    }

    /// The stream has not ended, so the desync is the close's result:
    /// its CLSE never goes out, however in step the connection was when
    /// the `Reader` was dropped.
    #[test]
    fn a_close_parked_past_the_reader_fails_with_a_later_desync() {
        let (reader, a, b, seen) = split_two_channels_delayed_ack(&[]);
        let writer = Writer::new(Arc::clone(&reader.shared));
        seen.stall_writes();
        let mut write = Box::pin(writer.write_channel(a, b"x"));
        assert!(poll_once(write.as_mut()).is_pending());
        let mut close = Box::pin(writer.close_channel(b));
        assert!(poll_once(close.as_mut()).is_pending());

        drop(reader);
        assert!(poll_once(close.as_mut()).is_pending());
        drop(write);
        let busy = now(writer.shared.write_half.lock());
        assert!(matches!(
            poll_once(close.as_mut()),
            Poll::Ready(Err(Error::Desynchronized))
        ));
        drop(busy);
    }

    /// A stale handle names the old channel, not the one that took its
    /// slot, which has another local id.
    #[test]
    fn a_stale_handle_closes_nothing_in_a_slot_taken_since() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1)).feed(&okay(2));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let stale = now(reader.open_channel(b"shell:\0")).unwrap();
        now(writer.close_channel(stale)).unwrap();
        let again = now(reader.open_channel(b"shell:\0")).unwrap();
        assert_eq!(again.slot(), stale.slot());
        assert_ne!(again.local_id(), stale.local_id());

        let err = now(writer.close_channel(stale)).unwrap_err();
        assert!(matches!(err, Error::ChannelClosed), "got {err:?}");
        assert_eq!(in_use(&writer), 1);
        assert_eq!(closes(&seen).len(), 1);
    }

    /// The old CLSE goes out ahead of the OPEN that takes the slot, and
    /// what the device still sends for the old channel is dropped.
    #[test]
    fn a_slot_taken_behind_a_dropped_close_hears_nothing_of_the_old_channel() {
        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1)).feed(&okay(2));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let old = now(reader.open_channel(b"shell:\0")).unwrap();
        let busy = now(writer.shared.write_half.lock());
        dropped_parked(writer.close_channel(old));
        drop(busy);

        let new = now(reader.open_channel(b"shell:\0")).unwrap();
        assert_eq!(new.slot(), old.slot());
        let sent = seen.sent();
        let tail: Vec<_> = sent[sent.len() - 2..]
            .iter()
            .map(|(cmd, arg0, arg1, _)| (*cmd, *arg0, *arg1))
            .collect();
        let local = new.local_id();
        assert_eq!(tail[0], (Command::Close, 1, 42));
        assert_eq!((tail[1].0, tail[1].1), (Command::Open, local));

        seen.feed(&wrte(1, b"for the old channel"));
        seen.feed(&wrte(local, b"for the new one"));
        let mut buf = [0u8; 32];
        let n = now(reader.read_channel(new, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"for the new one");
    }

    /// A channel closed while a read that cannot be dropped is under
    /// way. That read can then return a packet for the channel after
    /// the slot is freed and before the CLSE goes out.
    #[allow(clippy::type_complexity)]
    fn closed_with_a_read_under_way() -> (
        Pin<Box<impl Future<Output = Result<Infallible, Error<MockError>>>>>,
        Writer<SharedMock>,
        SharedMock,
    ) {
        let (mut run, writer, ch, seen) = read_under_way();
        let busy = now(writer.shared.write_half.lock());
        dropped_parked(writer.close_channel(ch));
        assert!(poll_once(run.as_mut()).is_pending());
        drop(busy);
        (run, writer, seen)
    }

    /// The OKAY for a WRTE that crossed the close is a READY for no
    /// channel, and gets a CLSE of its own, which adbd ignores.
    #[test]
    fn an_okay_behind_the_free_costs_a_second_clse() {
        let (mut run, writer, seen) = closed_with_a_read_under_way();
        seen.feed(&okay(1));
        assert!(poll_once(run.as_mut()).is_pending());
        assert!(writer.shared.lock_owed().is_empty());
        assert_eq!(closes(&seen), [(1, 42), (1, 42)]);
    }

    /// Data for a channel that is gone is nobody's, and owes no OKAY.
    #[test]
    fn a_write_behind_the_free_lands_nowhere() {
        let (mut run, writer, seen) = closed_with_a_read_under_way();
        seen.feed(&wrte(1, b"too late"));
        assert!(poll_once(run.as_mut()).is_pending());
        assert!(writer.shared.lock_owed().is_empty());
        assert_eq!(closes(&seen), [(1, 42)]);
        assert!(seen.acks_for(1).is_empty());
    }

    /// Every close is dropped behind a busy writer, and a read that
    /// cannot be dropped brings in one more packet. The list then holds
    /// all it can: the channels there were, the requests that took their
    /// slots, the one a dropped refusal left past the cap, and that
    /// packet. No OPEN of ours takes part, as it would send the list.
    /// `run` does the reading because it does not refuse the request
    /// past the cap on its way to the read.
    #[test]
    fn closes_owe_a_debt_for_every_channel_and_request_and_no_more() {
        const MAX_CHANNELS: usize = 2;
        let open_pkt = |remote: u32| Packet::new(Command::Open, remote, 0, b"tcp:80\0".to_vec());

        let mut mock = Mock::new();
        mock.feed(&cnxn()).feed(&okay(1)).feed(&okay(2));
        for remote in 70..73 {
            mock.feed(&open_pkt(remote));
        }
        mock.loses_cancelled_reads();
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(MAX_CHANNELS),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let a = now(reader.open_channel(b"shell:a\0")).unwrap();
        let b = now(reader.open_channel(b"shell:b\0")).unwrap();
        let listener = writer.listen_incoming();
        seen.parks_when_drained();

        now(reader.dispatch_one()).unwrap();
        now(reader.dispatch_one()).unwrap();
        let busy = now(writer.shared.write_half.lock());
        dropped_parked(reader.dispatch_one());
        drop(busy);
        assert_eq!(writer.shared.lock_incoming().len(), MAX_CHANNELS + 1);

        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        let dropped_close = |ch: ChannelId| {
            let busy = now(writer.shared.write_half.lock());
            dropped_parked(writer.close_channel(ch));
            drop(busy);
        };
        dropped_close(a);
        dropped_close(b);
        for _ in 0..=MAX_CHANNELS {
            let incoming = now(listener.accept()).unwrap();
            dropped_close(now(incoming.accept()).unwrap());
        }
        assert_eq!(writer.shared.lock_owed().len(), 2 * MAX_CHANNELS + 1);

        let busy = now(writer.shared.write_half.lock());
        seen.feed(&Packet::new(Command::Ready, 43, 9, Vec::new()));
        assert!(poll_once(run.as_mut()).is_pending());
        assert_eq!(writer.shared.lock_owed().len(), 2 * MAX_CHANNELS + 2);
        drop(busy);

        assert!(poll_once(run.as_mut()).is_pending());
        assert_eq!(closes(&seen).len(), 2 * MAX_CHANNELS + 2);
        assert!(writer.shared.lock_owed().is_empty());
    }

    #[test]
    fn a_channel_closes_once() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        now(writer.close_channel(ch)).unwrap();
        let err = now(writer.close_channel(ch)).unwrap_err();
        assert!(matches!(err, Error::ChannelClosed), "got {err:?}");
        assert_eq!(closes(&seen), [(1, 42)]);
    }

    /// `run` reaches the write half first, because of an older debt,
    /// and sends everything owed, so the close has nothing left to send
    /// or report.
    #[test]
    fn a_close_paid_by_run_has_nothing_left_to_do() {
        let (reader, a, b, seen) = split_two_channels_delayed_ack(&[]);
        let writer = Writer::new(Arc::clone(&reader.shared));
        seen.parks_when_drained();
        let mut run = Box::pin(reader.run());
        assert!(poll_once(run.as_mut()).is_pending());

        let busy = now(writer.shared.write_half.lock());
        dropped_parked(writer.close_channel(a));
        assert!(poll_once(run.as_mut()).is_pending());
        let mut close = Box::pin(writer.close_channel(b));
        assert!(poll_once(close.as_mut()).is_pending());
        drop(busy);

        assert!(poll_once(run.as_mut()).is_pending());
        assert_eq!(closes(&seen), [(1, 42), (2, 42)]);
        assert!(matches!(poll_once(close.as_mut()), Poll::Ready(Ok(()))));
        assert_eq!(closes(&seen), [(1, 42), (2, 42)]);
    }

    /// With the device gone a failed CLSE leaves the list empty, and
    /// the close reports no failure.
    #[test]
    fn a_close_to_a_device_that_is_gone_owes_nothing() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.fail_writes(ErrorKind::BrokenPipe);
        now(writer.close_channel(ch)).unwrap();
        assert!(writer.shared.lock_owed().is_empty());
        assert!(writer.shared.desync.check::<Infallible>().is_ok());
    }

    /// On a live connection a failed CLSE stays owed, as any packet
    /// does, behind the desync the failure raised.
    #[test]
    fn a_close_that_fails_keeps_what_it_owes() {
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(64, &[]);
        seen.fail_writes(ErrorKind::Other);
        let err = now(writer.close_channel(ch)).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
        assert_eq!(writer.shared.lock_owed().len(), 1);
        assert!(writer.shared.desync.check::<Infallible>().is_err());
    }

    #[test]
    fn a_failed_channel_closes_like_any_other() {
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(64, &[Packet::new(Command::Ready, 42, 1, Vec::new())]);
        now(reader.dispatch_one()).unwrap();
        assert_eq!(closes(&seen), [(1, 42)]);

        now(writer.close_channel(ch)).unwrap();
        assert_eq!(in_use(&writer), 0);
        assert_eq!(closes(&seen), [(1, 42), (1, 42)]);
    }
}
