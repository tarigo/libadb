//! Tests of the split halves, with the send queue, device-initiated
//! channels and back-pressure each in a module of its own.

use super::*;
use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
use crate::base::ids::{ChannelIds, LocalId, RemoteId};
use crate::base::mock::{
    abandon, now, okay, split_with_channel, withdraw, Mock, NoAuth, SharedMock,
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

    seen.feed(&Packet::new(Command::Open, 80, 0, b"tcp:80\0".to_vec()));
    let pump = |reader: &mut Reader<SharedMock, SharedMock>| {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        // Everything fed so far is dispatched on the way; the
        // drained mock then reports EOF, which is how the pump
        // knows the read went all the way through.
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Err(Error::UnexpectedEof)) => {}
            other => panic!("expected the drained-transport EOF, got {other:?}"),
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

    let pump = |reader: &mut Reader<SharedMock, SharedMock>| {
        let mut buf = [0u8; 16];
        let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Err(Error::UnexpectedEof)) => {}
            other => panic!("expected the drained-transport EOF, got {other:?}"),
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

#[test]
fn a_read_woken_on_a_desynchronized_connection_hands_out_nothing() {
    use core::task::{Context, Waker};

    // Index 1: the header is out, the payload write hangs.
    let (_reader, writer, ch) = split_with_channel(Some(1));
    let mut buf = [0u8; 8];
    let mut read = pin!(writer.read_channel(ch, &mut buf));
    assert!(read
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());

    // Data lands while another task abandons a packet mid-write.
    {
        let mut chs = writer.shared.lock_channels();
        let slot = chs.get_mut(ch).unwrap();
        slot.apply_write(b"hi").unwrap();
    }
    abandon(writer.write_channel(ch, b"payload-that-never-made-it"));

    let err = now(read).unwrap_err();
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
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
