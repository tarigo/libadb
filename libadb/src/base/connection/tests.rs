//! What a dropped write leaves behind on the wire.

use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::task::Poll;

use super::*;
use crate::base::mock::{
    abandon, clse, cnxn, connected_for_select, connected_with_channel, now, stls,
    two_channels_classic, two_channels_delayed_ack, wrte, Mock, MockError, NoAuth, Signs,
    Withholds,
};
use crate::base::protocol::command::{Command, AUTH_RSAPUBLICKEY, AUTH_SIGNATURE, AUTH_TOKEN};
use crate::base::protocol::Packet;
use crate::error::{AuthError, ProtocolError};

#[test]
fn a_write_cancelled_between_header_and_payload_desyncs_the_connection() {
    // Index 1: the header lands, the payload write is the one that hangs.
    let (mut conn, ch) = connected_with_channel(Some(1));
    abandon(conn.write_channel(ch, b"payload-that-never-made-it"));

    let err = now(conn.write_channel(ch, b"more")).unwrap_err();
    assert!(
        matches!(err, Error::Desynchronized),
        "expected Desynchronized, got {err:?}"
    );
}

#[test]
fn a_desynchronized_connection_refuses_every_operation() {
    let (mut conn, ch) = connected_with_channel(Some(1));
    abandon(conn.write_channel(ch, b"payload-that-never-made-it"));

    assert!(matches!(
        now(conn.open_channel(b"shell:\0")),
        Err(Error::Desynchronized)
    ));
    let mut buf = [0u8; 16];
    assert!(matches!(
        now(conn.read_channel(ch, &mut buf)),
        Err(Error::Desynchronized)
    ));
    assert!(matches!(
        now(conn.close_channel(ch)),
        Err(Error::Desynchronized)
    ));
    assert!(matches!(
        now(conn.select_channel(ch, &mut buf, core::future::pending::<()>())),
        Err(Error::Desynchronized)
    ));
}

/// What had arrived for a channel by the time a write was given up on
/// is the device's to have delivered: reads get it, and then the error.
#[test]
fn a_desync_leaves_what_arrived_readable() {
    let (mut conn, a, b) = two_channels_delayed_ack(
        4096,
        &[wrte(2, b"for-b-first"), wrte(2, b"-second"), wrte(1, b"x")],
    );
    let mut buf = [0u8; 32];
    now(conn.read_channel(a, &mut buf)).unwrap();

    // The header goes, and the payload is what hangs.
    conn.transport_mut().stall_writes();
    abandon(conn.write_channel(a, b"payload-that-never-made-it"));
    assert!(matches!(
        now(conn.write_channel(a, b"more")),
        Err(Error::Desynchronized)
    ));

    let mut got = Vec::new();
    let err = loop {
        match now(conn.read_channel(b, &mut buf[..4])) {
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => break e,
        }
    };
    assert_eq!(got, b"for-b-first-second", "in the order it came");
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// The failure of an OKAY is the connection's, whether the bytes it is
/// for sat in the slot or came straight off the wire.
#[test]
fn a_failed_okay_costs_a_read_nothing() {
    use embedded_io::ErrorKind;

    // Buffered: a read of `a` leaves `b`'s packet in its slot.
    let (mut conn, a, b) = two_channels_delayed_ack(4096, &[wrte(2, b"for-b"), wrte(1, b"x")]);
    let mut buf = [0u8; 32];
    now(conn.read_channel(a, &mut buf)).unwrap();
    conn.transport_mut().fail_writes(ErrorKind::Other);
    let n = now(conn.read_channel(b, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"for-b");
    assert!(matches!(
        now(conn.read_channel(b, &mut buf)),
        Err(Error::Desynchronized)
    ));

    // Off the wire, in a read the packet fits and in one it does not.
    for size in [32, 2] {
        let (mut conn, a, _) = two_channels_delayed_ack(4096, &[wrte(1, b"for-a")]);
        conn.transport_mut().fail_writes(ErrorKind::Other);
        let mut got = Vec::new();
        let err = loop {
            match now(conn.read_channel(a, &mut buf[..size])) {
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => break e,
            }
        };
        assert_eq!(got, b"for-a", "reads of {size}");
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
    }
}

/// A write that fails because the device is gone leaves no stream to
/// fall out of step with: the read goes on to what it sent before going.
#[test]
fn an_okay_to_a_device_that_is_gone_stops_no_read() {
    use embedded_io::ErrorKind;

    let (mut conn, a, _) =
        two_channels_delayed_ack(4096, &[wrte(1, b"one"), wrte(1, b"two"), clse(1)]);
    conn.transport_mut().fail_writes(ErrorKind::BrokenPipe);
    let mut buf = [0u8; 32];
    let n = now(conn.read_channel(a, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"one");
    let n = now(conn.read_channel(a, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"two");
    assert!(matches!(
        now(conn.read_channel(a, &mut buf)),
        Err(Error::ChannelClosed)
    ));
}

/// Without delayed ACK a packet is acknowledged as it lands, and that
/// stops neither the read it is for nor the packets behind it.
#[test]
fn a_failed_okay_for_another_channel_stops_no_read_of_what_is_left() {
    use embedded_io::ErrorKind;

    let (mut conn, a, b) = two_channels_classic(
        ConnectionConfig::new(),
        &[wrte(2, b"for-b"), wrte(1, b"for-a")],
    );
    conn.transport_mut().fail_writes(ErrorKind::BrokenPipe);
    let mut buf = [0u8; 32];
    let n = now(conn.read_channel(a, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"for-a");
    let n = now(conn.read_channel(b, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"for-b");
}

/// Everything left to read on `ch`, in as many reads as that takes, and
/// what ended them.
fn read_to_the_end(conn: &mut Connection<Mock>, ch: ChannelId) -> (Vec<u8>, Error<MockError>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 32];
    loop {
        match now(conn.read_channel(ch, &mut buf)) {
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => return (got, e),
        }
    }
}

/// A read dropped during its OKAY has taken nothing from the slot, so
/// the next reads come back with all of it, not past a gap.
#[test]
fn a_read_dropped_writing_its_okay_leaves_no_gap() {
    let (mut conn, a, b) = two_channels_delayed_ack(4096, &[wrte(2, b"for-b"), wrte(1, b"x")]);
    let mut buf = [0u8; 32];
    now(conn.read_channel(a, &mut buf)).unwrap();

    conn.transport_mut().stall_writes();
    abandon(conn.read_channel(b, &mut buf[..2]));

    let (got, err) = read_to_the_end(&mut conn, b);
    assert_eq!(got, b"for-b");
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// The same for a packet off the wire that does not fit the read: what
/// is left of it must not read on as if nothing came before it.
#[test]
fn a_read_dropped_writing_the_okay_of_a_packet_it_split_leaves_no_gap() {
    let (mut conn, a, _) = two_channels_delayed_ack(4096, &[wrte(1, b"for-a")]);
    conn.transport_mut().stall_writes();
    let mut buf = [0u8; 32];
    abandon(conn.read_channel(a, &mut buf[..2]));

    let (got, err) = read_to_the_end(&mut conn, a);
    assert_eq!(got, b"for-a");
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");
}

/// One that fits went straight to the dropped call, and there is
/// nothing left to read past: the next read says so, rather than go
/// back to the wire with the packet missing.
#[test]
fn a_read_dropped_writing_the_okay_of_a_whole_packet_fails_the_next() {
    let (mut conn, a, _) = two_channels_delayed_ack(4096, &[wrte(1, b"for-a"), wrte(1, b"more")]);
    conn.transport_mut().stall_writes();
    let mut buf = [0u8; 32];
    abandon(conn.read_channel(a, &mut buf));

    assert!(matches!(
        now(conn.read_channel(a, &mut buf)),
        Err(Error::Desynchronized)
    ));
}

#[test]
fn a_write_that_completes_leaves_the_connection_usable() {
    let (mut conn, ch) = connected_with_channel(None);
    now(conn.write_channel(ch, b"payload")).unwrap();
    now(conn.write_channel(ch, b"another")).unwrap();
}

#[test]
fn a_write_cancelled_before_the_header_is_treated_as_broken_too() {
    // Index 0: the write was polled but never returned, so we cannot
    // tell whether the transport already took bytes from us. The
    // connection is written off rather than guessed about.
    let (mut conn, ch) = connected_with_channel(Some(0));
    abandon(conn.write_channel(ch, b"payload"));

    let err = now(conn.write_channel(ch, b"more")).unwrap_err();
    assert!(
        matches!(err, Error::Desynchronized),
        "expected Desynchronized, got {err:?}"
    );
}

/// An interrupt that only becomes ready on its `n`-th poll, so it can
/// win the race with a read that is already in flight.
fn ready_on_poll(n: usize) -> impl Future<Output = &'static str> {
    let mut polls = 0;
    core::future::poll_fn(move |cx| {
        polls += 1;
        if polls >= n {
            Poll::Ready("interrupted")
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
}

#[test]
fn a_transport_that_loses_cancelled_reads_finishes_the_read_first() {
    let (mut conn, ch) = connected_for_select(|m| {
        m.loses_cancelled_reads().slow_reads(1);
    });

    // The interrupt comes due while the read is in flight. Dropping the
    // read here would cost us the bytes the device already sent, so the
    // read has to finish and the data comes back instead.
    let out = now(conn.select_channel(ch, &mut [0u8; 32], ready_on_poll(2))).unwrap();
    assert!(
        matches!(out, SelectResult::Data(5)),
        "expected the payload, got {out:?}"
    );
}

#[test]
fn a_transport_that_keeps_cancelled_reads_lets_the_interrupt_win() {
    let (mut conn, ch) = connected_for_select(|m| {
        m.slow_reads(1);
    });

    let out = now(conn.select_channel(ch, &mut [0u8; 32], ready_on_poll(2))).unwrap();
    assert!(
        matches!(out, SelectResult::Interrupted("interrupted")),
        "expected the interrupt, got {out:?}"
    );
}

#[test]
fn an_interrupt_that_is_already_due_wins_on_either_transport() {
    for lossy in [false, true] {
        let (mut conn, ch) = connected_for_select(|m| {
            if lossy {
                m.loses_cancelled_reads();
            }
        });
        let out = now(conn.select_channel(ch, &mut [0u8; 32], ready_on_poll(1))).unwrap();
        assert!(
            matches!(out, SelectResult::Interrupted("interrupted")),
            "lossy={lossy}: expected the interrupt, got {out:?}"
        );
    }
}

#[test]
fn a_read_after_an_interrupt_mid_packet_finishes_that_packet() {
    // Seven bytes a read: four reads bring the header and "hell", and
    // the interrupt comes due before the fifth.
    for lossy in [false, true] {
        let (mut conn, ch) = connected_for_select(|m| {
            m.drips(7);
            if lossy {
                m.loses_cancelled_reads();
            }
        });

        let out = now(conn.select_channel(ch, &mut [0u8; 32], ready_on_poll(5))).unwrap();
        assert!(
            matches!(out, SelectResult::Interrupted("interrupted")),
            "lossy={lossy}: expected the interrupt, got {out:?}"
        );
        let held = conn.recv_buf.len();
        assert!(
            0 < held && held < 24 + 5,
            "lossy={lossy}: the interrupt has to land mid-packet, {held} bytes were in"
        );

        let mut buf = [0u8; 32];
        let n = now(conn.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"hello", "lossy={lossy}");
    }
}

// ---------------------------------------------------------------------------
// Acknowledging what was consumed, not what arrived
// ---------------------------------------------------------------------------

#[test]
fn a_write_nobody_has_read_is_not_acknowledged() {
    // The device writes to channel B, then to A. Reading A dispatches
    // B's packet into its buffer along the way.
    let (mut conn, a, _b) =
        two_channels_delayed_ack(64 * 1024, &[wrte(2, b"for-b"), wrte(1, b"for-a")]);

    let mut buf = [0u8; 32];
    let n = now(conn.read_channel(a, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"for-a");

    assert_eq!(
        conn.transport().acks_for(1),
        vec![5],
        "the channel that was read is acknowledged"
    );
    assert!(
        conn.transport().acks_for(2).is_empty(),
        "the channel nobody read must not have its credit returned"
    );
}

#[test]
fn reading_a_buffered_write_acknowledges_it() {
    let (mut conn, a, b) =
        two_channels_delayed_ack(64 * 1024, &[wrte(2, b"for-b"), wrte(1, b"for-a")]);

    let mut buf = [0u8; 32];
    now(conn.read_channel(a, &mut buf)).unwrap();
    let n = now(conn.read_channel(b, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"for-b");

    assert_eq!(
        conn.transport().acks_for(2),
        vec![5],
        "credit is returned once the application takes the bytes"
    );
}

#[test]
fn a_partial_read_acknowledges_only_what_was_taken() {
    let (mut conn, a, _b) = two_channels_delayed_ack(64 * 1024, &[wrte(1, b"0123456789")]);

    let mut buf = [0u8; 4];
    let n = now(conn.read_channel(a, &mut buf)).unwrap();
    assert_eq!(n, 4);
    assert_eq!(conn.transport().acks_for(1), vec![4]);

    let n = now(conn.read_channel(a, &mut buf)).unwrap();
    assert_eq!(n, 4);
    assert_eq!(conn.transport().acks_for(1), vec![4, 4]);
}

#[test]
fn a_classic_channel_is_acknowledged_until_the_watermark() {
    // Watermark lands at 1 KiB: max_payload and the advertised budget
    // are both 1 KiB, and the hard cap is above both.
    let config = ConnectionConfig::new()
        .with_max_payload(1024)
        .with_initial_ack_bytes(1024)
        .with_max_rx_per_channel(8 * 1024);
    assert_eq!(config.rx_watermark(), 1024);

    let (mut conn, a, _b) = two_channels_classic(
        config,
        &[
            wrte(2, &[b'x'; 700]),
            wrte(2, &[b'y'; 700]),
            wrte(1, b"done"),
        ],
    );

    let mut buf = [0u8; 16];
    now(conn.read_channel(a, &mut buf)).unwrap();

    assert_eq!(
        conn.transport().acks_for(2).len(),
        1,
        "the first write fits under the watermark and is acknowledged; \
         the second takes the channel over it and waits for a reader"
    );
}

#[test]
fn reading_past_the_watermark_releases_the_held_ack() {
    let config = ConnectionConfig::new()
        .with_max_payload(1024)
        .with_initial_ack_bytes(1024)
        .with_max_rx_per_channel(8 * 1024);
    let (mut conn, a, b) = two_channels_classic(
        config,
        &[
            wrte(2, &[b'x'; 700]),
            wrte(2, &[b'y'; 700]),
            wrte(1, b"done"),
        ],
    );

    let mut buf = [0u8; 16];
    now(conn.read_channel(a, &mut buf)).unwrap();
    let mut big = [0u8; 1400];
    now(conn.read_channel(b, &mut big)).unwrap();

    assert_eq!(
        conn.transport().acks_for(2).len(),
        2,
        "draining the channel lets the held acknowledgement out"
    );
}

mod incoming {
    use super::*;
    use crate::base::mock::{
        cnxn_with, now, one_slot, withdraw, wrte, Mock, NoAuth, FAILED_WRITES,
    };
    use embedded_io::ErrorKind;

    fn connected(host: &'static [u8], device: &str) -> Connection<Mock> {
        let mut mock = Mock::new();
        mock.feed(&cnxn_with(device));
        now(Connection::connect(
            mock,
            NoAuth,
            HostBanner::Raw(host),
            ConnectionConfig::new(),
        ))
        .unwrap()
    }

    fn open_pkt(remote_id: u32, credit: u32, dest: &[u8]) -> Packet {
        Packet::new(Command::Open, remote_id, credit, dest.to_vec())
    }

    #[test]
    fn a_device_open_is_queued_accepted_and_serves_data() {
        let mut conn = connected(
            b"host::features=shell_v2,delayed_ack",
            "shell_v2,delayed_ack",
        );
        conn.transport.feed(&open_pkt(77, 4096, b"tcp:9090\0"));

        let incoming = now(conn.accept_incoming()).unwrap();
        assert_eq!(incoming.destination(), b"tcp:9090\0");
        let ch = now(incoming.accept()).unwrap();

        // READY named our id and carried our receive credit.
        let (cmd, local, remote, payload) = conn.transport.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Ready);
        assert_eq!(remote, 77);
        assert_ne!(local, 0);
        assert_eq!(payload.len(), 4);

        // Their WRTE reaches the accepted channel...
        conn.transport.feed(&wrte(local, b"ping"));
        let mut buf = [0u8; 16];
        let n = now(conn.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"ping");

        // ...and our write spends the budget the OPEN granted.
        now(conn.write_channel(ch, b"pong")).unwrap();
        let (cmd, l, r, payload) = conn.transport.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Write);
        assert_eq!((l, r), (local, 77));
        assert_eq!(payload, b"pong");
    }

    #[test]
    fn a_rejected_open_answers_clse_with_no_local_id() {
        let mut conn = connected(b"host::features=shell_v2", "shell_v2");
        conn.transport.feed(&open_pkt(88, 0, b"tcp:1\0"));

        let incoming = now(conn.accept_incoming()).unwrap();
        now(incoming.reject()).unwrap();

        let (cmd, local, remote, _) = conn.transport.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Close);
        assert_eq!((local, remote), (0, 88));
    }

    #[test]
    fn a_dropped_verdict_returns_the_request_to_the_queue() {
        let mut conn = connected(b"host::features=shell_v2", "shell_v2");
        conn.transport.feed(&open_pkt(99, 0, b"tcp:2\0"));

        let incoming = now(conn.accept_incoming()).unwrap();
        drop(incoming);

        let incoming = conn.try_accept_incoming().expect("request lost on drop");
        assert_eq!(incoming.destination(), b"tcp:2\0");
    }

    #[test]
    fn a_full_queue_refuses_new_opens_on_arrival() {
        let mut mock = Mock::new();
        mock.feed(&cnxn_with("shell_v2"));
        let mut conn = now(Connection::connect(
            mock,
            NoAuth,
            HostBanner::Raw(b"host::features=shell_v2"),
            ConnectionConfig::new().with_max_channels(2),
        ))
        .unwrap();

        now(conn.dispatch(open_pkt(1, 0, b"tcp:1\0"))).unwrap();
        now(conn.dispatch(open_pkt(2, 0, b"tcp:2\0"))).unwrap();
        now(conn.dispatch(open_pkt(3, 0, b"tcp:3\0"))).unwrap();

        let (cmd, local, remote, _) = conn.transport.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Close, "the third OPEN must be refused");
        assert_eq!((local, remote), (0, 3));

        // Undecided handles bounce back on drop, so resolve them.
        now(conn.try_accept_incoming().unwrap().reject()).unwrap();
        now(conn.try_accept_incoming().unwrap().reject()).unwrap();
        assert!(conn.try_accept_incoming().is_none());
    }

    #[test]
    fn a_device_cancel_removes_the_pending_request() {
        let mut conn = connected(b"host::features=shell_v2", "shell_v2");
        now(conn.dispatch(open_pkt(55, 0, b"tcp:5\0"))).unwrap();
        now(conn.dispatch(withdraw(55))).unwrap();
        assert!(conn.try_accept_incoming().is_none());
    }

    #[test]
    fn a_withdrawal_racing_the_accept_closes_the_slot() {
        // The zero-local-id CLSE was buffered behind the OPEN: by the
        // time it is dispatched, the request is an accepted slot, not
        // a queued one — it must close like any remote CLSE.
        let mut conn = connected(b"host::features=shell_v2", "shell_v2");
        now(conn.dispatch(open_pkt(90, 0, b"tcp:9\0"))).unwrap();
        let ch = now(conn.try_accept_incoming().unwrap().accept()).unwrap();

        now(conn.dispatch(withdraw(90))).unwrap();

        let mut buf = [0u8; 8];
        let err = now(conn.read_channel(ch, &mut buf)).unwrap_err();
        assert!(
            matches!(err, Error::ChannelClosed),
            "expected ChannelClosed, got {err:?}"
        );
    }

    #[test]
    fn a_cancelled_accept_frees_the_slot_and_requeues() {
        use core::task::{Context, Poll, Waker};

        // A transport whose write parks forever: accept reserves a slot,
        // sends READY, and hangs — the exact window a cancel lands in.
        let mut mock = Mock::new();
        mock.feed(&cnxn_with("shell_v2"));
        // CNXN writes header+payload (two calls); the empty-payload READY
        // that accept sends is the very next write.
        mock.stall_write(2);
        let mut conn = now(Connection::connect(
            mock,
            NoAuth,
            HostBanner::Raw(b"host::features=shell_v2"),
            ConnectionConfig::new(),
        ))
        .unwrap();

        now(conn.dispatch(open_pkt(66, 0, b"tcp:6\0"))).unwrap();
        {
            let incoming = conn.try_accept_incoming().unwrap();
            let mut fut = core::pin::pin!(incoming.accept());
            let mut cx = Context::from_waker(Waker::noop());
            // Poll once: the slot is reserved, the READY write stalls.
            assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
            // Drop mid-flight — cancellation.
        }

        // The reserved slot came back: the table is empty again.
        assert!(
            conn.table.in_use() == 0,
            "the reserved slot leaked past the cancel"
        );
        // The request came back too: it is acceptable again.
        let again = conn.try_accept_incoming().expect("request lost on cancel");
        assert_eq!(again.destination(), b"tcp:6\0");
    }

    /// A device that is gone leaves nobody to answer, so a verdict that
    /// finds that consumes the request, and a caller that carries on gets
    /// to the packet behind it and the end of the stream, rather than be
    /// handed the same request for ever. Any other failure leaves the
    /// request in the queue, behind the desync it raised.
    fn assert_next_call_after_failing_on(
        kind: ErrorKind,
        left: usize,
        conn: &mut Connection<Mock>,
        ch: ChannelId,
    ) {
        let next = now(conn.accept_incoming()).map(|_| ()).unwrap_err();
        if left == 0 {
            assert!(matches!(next, Error::UnexpectedEof), "{kind:?}: {next:?}");
            let mut buf = [0u8; 16];
            let n = now(conn.read_channel(ch, &mut buf)).unwrap();
            assert_eq!(&buf[..n], b"behind it", "{kind:?}");
        } else {
            assert!(matches!(next, Error::Desynchronized), "{kind:?}: {next:?}");
        }
        assert_eq!(conn.incoming.len(), left, "{kind:?}");
    }

    /// A connection with a channel open and a slot to spare, a request
    /// queued on it, a packet behind that, and every write failing with
    /// `kind`.
    fn request_failing_with(kind: ErrorKind) -> (Connection<Mock>, ChannelId) {
        let (mut conn, ch) = connected_with_channel(None);
        conn.transport.feed(&open_pkt(77, 0, b"tcp:80\0"));
        conn.transport.feed(&wrte(1, b"behind it"));
        conn.transport.fail_writes(kind);
        (conn, ch)
    }

    /// A READY, whose slot goes back whatever becomes of the request.
    #[test]
    fn an_accept_that_fails_keeps_the_request_unless_the_device_is_gone() {
        for (kind, left) in FAILED_WRITES {
            let (mut conn, ch) = request_failing_with(kind);

            let incoming = now(conn.accept_incoming()).unwrap();
            let err = now(incoming.accept()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");
            assert_eq!(conn.table.in_use(), 1, "{kind:?}");

            assert_next_call_after_failing_on(kind, left, &mut conn, ch);
        }
    }

    /// With no slot to give, an accept is a refusal, and goes the same
    /// way.
    #[test]
    fn an_accept_with_no_slot_that_fails_keeps_the_request_unless_the_device_is_gone() {
        let queued = [open_pkt(77, 0, b"tcp:80\0"), wrte(1, b"behind it")];
        for (kind, left) in FAILED_WRITES {
            let mut conn = one_slot("shell_v2", &queued);
            let ch = now(conn.open_channel(b"shell:\0")).unwrap();
            conn.transport.fail_writes(kind);

            let incoming = now(conn.accept_incoming()).unwrap();
            let err = now(incoming.accept()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");

            assert_next_call_after_failing_on(kind, left, &mut conn, ch);
        }
    }

    /// A refusal the caller asked for goes the same way again.
    #[test]
    fn a_reject_that_fails_keeps_the_request_unless_the_device_is_gone() {
        for (kind, left) in FAILED_WRITES {
            let (mut conn, ch) = request_failing_with(kind);

            let incoming = now(conn.accept_incoming()).unwrap();
            let err = now(incoming.reject()).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{kind:?}: got {err:?}");

            assert_next_call_after_failing_on(kind, left, &mut conn, ch);
        }
    }

    #[test]
    fn the_ready_credit_is_clamped_to_the_receive_cap() {
        let mut mock = Mock::new();
        mock.feed(&cnxn_with("shell_v2,delayed_ack"));
        let config = ConnectionConfig::new()
            .with_initial_ack_bytes(32 * 1024 * 1024)
            .with_max_rx_per_channel(1024 * 1024);
        let mut conn = now(Connection::connect(
            mock,
            NoAuth,
            HostBanner::Raw(b"host::features=shell_v2,delayed_ack"),
            config,
        ))
        .unwrap();

        now(conn.dispatch(open_pkt(7, 0, b"tcp:7\0"))).unwrap();
        let incoming = conn.try_accept_incoming().unwrap();
        now(incoming.accept()).unwrap();

        let (cmd, _, _, payload) = conn.transport.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Ready);
        assert_eq!(payload, (1024u32 * 1024).to_le_bytes());
    }

    #[test]
    fn accept_with_no_free_slot_refuses_and_reports() {
        let mut mock = Mock::new();
        mock.feed(&cnxn_with("shell_v2"));
        mock.feed(&crate::base::mock::okay(1));
        let mut conn = now(Connection::connect(
            mock,
            NoAuth,
            HostBanner::Raw(b"host::features=shell_v2"),
            ConnectionConfig::new().with_max_channels(1),
        ))
        .unwrap();
        let _busy = now(conn.open_channel(b"shell:\0")).unwrap();

        now(conn.dispatch(open_pkt(9, 0, b"tcp:9\0"))).unwrap();
        let incoming = conn.try_accept_incoming().unwrap();
        let err = now(incoming.accept()).unwrap_err();
        assert!(matches!(err, Error::NoFreeChannels), "got {err:?}");

        let (cmd, local, remote, _) = conn.transport.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Close);
        assert_eq!((local, remote), (0, 9));
    }
}

#[test]
fn a_device_that_answers_the_handshake_with_stls_says_it_wants_tls() {
    let mut mock = Mock::new();
    mock.feed(&stls());

    let Err(err) = now(Connection::connect(
        mock,
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    )) else {
        panic!("expected the handshake to refuse a TLS-only device");
    };

    assert!(
        matches!(err, Error::Protocol(ProtocolError::TlsRequired)),
        "expected TlsRequired, got {err:?}"
    );
}

/// The banner's property cap is the config's: one property past it
/// fails the handshake, and exactly as many connect.
#[test]
fn the_banner_property_cap_comes_from_the_config() {
    let banner = b"device::ro.product.name=a;ro.product.model=b;features=shell_v2";
    let connect = |cap: usize| {
        let mut mock = Mock::new();
        mock.feed(&Packet::new(
            Command::Connect,
            crate::base::protocol::command::ADB_VERSION,
            256 * 1024,
            banner.to_vec(),
        ));
        let config = ConnectionConfig::new().with_max_banner_properties(cap);
        now(Connection::connect(
            mock,
            NoAuth,
            HostBanner::Features(&[]),
            config,
        ))
    };

    let Err(err) = connect(1) else {
        panic!("two properties must not fit a cap of one");
    };
    assert!(
        matches!(err, Error::Protocol(ProtocolError::TooManyBannerProperties)),
        "expected TooManyBannerProperties, got {err:?}"
    );

    let conn = connect(2).unwrap();
    let parsed = conn.device_banner_parsed();
    assert_eq!(parsed.product_model(), Some("b"));
}

#[test]
fn an_auth_that_is_not_a_token_after_our_signature_is_a_rejection() {
    // The device answered the signature with AUTH again, but not with a
    // token. That is not a CNXN and must not be assembled into one: a
    // connection built from it would carry an AUTH payload as its
    // banner and believe itself authenticated.
    let mut mock = Mock::new();
    mock.feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x5a; 20]));
    mock.feed(&Packet::new(Command::Auth, AUTH_SIGNATURE, 0, vec![]));

    let Err(err) = now(Connection::connect(
        mock,
        Signs,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    )) else {
        panic!("a stray AUTH must not become a connection");
    };

    assert!(
        matches!(err, Error::Auth(AuthError::Rejected)),
        "expected Rejected, got {err:?}"
    );
}

#[test]
fn a_withheld_key_ends_the_handshake_untrusted_before_it_reaches_the_device() {
    // The second token asks for the key. Sending it is what raises the
    // dialog on the device, so an authenticator that withholds it must
    // leave the signature as the last thing on the wire.
    let mut mock = Mock::new();
    mock.feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x5a; 20]));
    mock.feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x6b; 20]));

    let Err(err) = now(Connection::connect(
        &mut mock,
        Withholds,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    )) else {
        panic!("an untrusted key must not become a connection");
    };

    assert!(
        matches!(err, Error::Auth(AuthError::KeyNotTrusted)),
        "expected KeyNotTrusted, got {err:?}"
    );
    let sent = mock.sent();
    assert!(
        !sent
            .iter()
            .any(|(c, arg0, ..)| *c == Command::Auth && *arg0 == AUTH_RSAPUBLICKEY),
        "the key must not be offered, sent {sent:?}"
    );
    assert_eq!(
        sent.last().map(|(c, arg0, ..)| (*c, *arg0)),
        Some((Command::Auth, AUTH_SIGNATURE)),
        "the handshake must end on our signature"
    );
}

#[test]
fn a_trusted_key_connects_without_being_offered() {
    let mut mock = Mock::new();
    mock.feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x5a; 20]));
    mock.feed(&cnxn());

    now(Connection::connect(
        mock,
        Withholds,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .expect("a device that accepts the signature never asks for the key");
}

#[test]
fn a_borrowed_authenticator_withholds_its_key_as_the_owned_one_does() {
    let mut mock = Mock::new();
    mock.feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x5a; 20]));
    mock.feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x6b; 20]));
    let mut auth = Withholds;

    let Err(err) = now(Connection::connect(
        mock,
        &mut auth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    )) else {
        panic!("an untrusted key must not become a connection");
    };

    assert!(
        matches!(err, Error::Auth(AuthError::KeyNotTrusted)),
        "expected KeyNotTrusted, got {err:?}"
    );
}

#[test]
fn a_large_packet_is_zeroed_once_while_select_reads_it() {
    // Raced against an interrupt, the read still stages the packet once,
    // as `recv_pkt` does in its twin test in wire.rs, and must not zero
    // it again for each 16 KiB read that TLS hands over. The bound
    // allows the header and the MIN_READ that a first read is padded to.
    let big = vec![0x5a; 256 * 1024];
    let (mut conn, ch) = connected_for_select(|mock| {
        mock.feed(&wrte(1, &big)).drips(16 * 1024);
    });
    let mut buf = vec![0u8; big.len()];
    let first = now(conn.select_channel(ch, &mut buf, core::future::pending::<()>())).unwrap();
    assert!(
        matches!(first, SelectResult::Data(5)),
        "the small WRTE first"
    );

    crate::base::wire::ZEROED.with(|zeroed| zeroed.set(0));
    let mut got = 0;
    while got < big.len() {
        match now(conn.select_channel(ch, &mut buf[got..], core::future::pending::<()>())).unwrap()
        {
            SelectResult::Data(n) => got += n,
            SelectResult::Interrupted(()) => unreachable!("the interrupt never fires"),
        }
    }

    assert_eq!(buf, big);
    let zeroed = crate::base::wire::ZEROED.with(|zeroed| zeroed.get());
    assert!(
        zeroed <= big.len() + 24 + crate::base::wire::MIN_READ,
        "zeroed {zeroed} bytes for a {}-byte payload",
        big.len()
    );
}

#[test]
fn a_handshake_packet_after_the_handshake_is_dropped_and_the_session_goes_on() {
    // Out of turn, so dropped like any packet nobody claims, with a line
    // in the log; the channel read behind it is none the worse.
    let (mut conn, ch) = connected_with_channel(None);
    conn.transport_mut()
        .feed(&Packet::new(
            Command::StartTls,
            crate::base::protocol::constant::STLS_VERSION,
            0,
            vec![],
        ))
        .feed(&Packet::new(
            Command::Connect,
            crate::base::protocol::command::ADB_VERSION,
            4096,
            b"device::".to_vec(),
        ))
        .feed(&Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![0x5a; 20]))
        .feed(&wrte(1, b"after"));

    let mut buf = [0u8; 16];
    let n = now(conn.read_channel(ch, &mut buf)).unwrap();

    assert_eq!(&buf[..n], b"after");
}

/// Nothing frees a slot but a close, a `Channel` having no `Drop`, so
/// whatever opened a channel has to close it on every way out.
mod slot_tests {
    use super::*;
    use crate::base::mock::{one_slot, shell_frame, FAILED_WRITES};
    use crate::shell::v2::{self as shell_v2, CommandOutput, FrameId, Shell, WindowSize};
    use crate::{cmd, logcat};
    use embedded_io::ErrorKind;

    /// The first write past the handshake and one OPEN, each of which
    /// takes a header and a payload.
    const FIRST_WRITE: usize = 4;

    /// What is left of a slot after `err`, the failure of the first
    /// write on the channel: nothing, unless that desynchronized the
    /// connection, on which no close gets anywhere and no later call
    /// gets as far as wanting the slot.
    fn assert_failed_with(err: &Error<MockError>, kind: ErrorKind, in_use: usize, left: usize) {
        assert!(
            matches!(err, Error::Io(e) if embedded_io::Error::kind(e) == kind),
            "{kind:?}: {err:?}"
        );
        assert_eq!(in_use, left, "{kind:?}");
    }

    /// `collect` on a shell over a connection of one slot, whose device
    /// follows up its READY with `then`.
    fn collected(then: &[Packet]) -> (Connection<Mock>, Result<CommandOutput, Error<MockError>>) {
        let mut conn = one_slot("shell_v2", then);
        let mut rx = [0u8; 64];
        let channel = now(conn.open(b"shell,v2,raw:x\0")).unwrap();
        let output = now(Shell::new(channel, &mut rx).collect());
        (conn, output)
    }

    #[test]
    fn collect_gives_the_slot_back_when_the_device_closes_with_no_exit_frame() {
        let stdout = shell_frame(FrameId::Stdout, b"so far");
        let (conn, output) = collected(&[wrte(1, &stdout), clse(1)]);
        assert!(matches!(output, Err(Error::ChannelClosed)), "{output:?}");
        assert_eq!(conn.table.in_use(), 0);
    }

    #[test]
    fn collect_gives_the_slot_back_when_a_read_fails() {
        let stdout = shell_frame(FrameId::Stdout, b"so far");
        let (conn, output) = collected(&[wrte(1, &stdout)]);
        assert!(matches!(output, Err(Error::UnexpectedEof)), "{output:?}");
        assert_eq!(conn.table.in_use(), 0);
    }

    #[test]
    fn collect_gives_the_slot_back_on_a_protocol_error() {
        let (conn, output) = collected(&[wrte(1, &shell_frame(FrameId::Exit, &[]))]);
        assert!(
            matches!(
                output,
                Err(Error::Protocol(ProtocolError::ShortExitPayload))
            ),
            "{output:?}"
        );
        assert_eq!(conn.table.in_use(), 0);
    }

    /// The command finished and said so: what comes after that has no
    /// bearing on its output. The frames land ahead of the read, for
    /// their OKAYs to get out before the writes start failing.
    #[test]
    fn collect_keeps_a_finished_commands_output_when_its_close_fails() {
        for (kind, _) in FAILED_WRITES {
            let mut conn = one_slot("shell_v2", &[]);
            let mut rx = [0u8; 64];
            let channel = now(conn.open(b"shell,v2,raw:x\0")).unwrap();
            for frame in [
                shell_frame(FrameId::Stdout, b"out"),
                shell_frame(FrameId::Stderr, b"err"),
                shell_frame(FrameId::Exit, &[7]),
            ] {
                now(channel.session.dispatch(wrte(1, &frame))).unwrap();
            }
            channel.session.transport.fail_writes(kind);

            let output = now(Shell::new(channel, &mut rx).collect()).unwrap();
            assert_eq!(output.stdout, b"out", "{kind:?}");
            assert_eq!(output.stderr, b"err", "{kind:?}");
            assert_eq!(output.exit_code, 7, "{kind:?}");
        }
    }

    type OneShot = fn(&mut Connection<Mock>, &mut [u8]) -> Result<(), Error<MockError>>;

    /// The calls that close a command's stdin for it and collect what it
    /// wrote.
    const ONE_SHOTS: [OneShot; 3] = [
        |conn, rx| now(shell_v2::exec(conn, "x", rx)).map(drop),
        |conn, rx| now(cmd::exec(conn, &["x"], rx)).map(drop),
        |conn, rx| now(logcat::exec_text(conn, &["-d"], rx)).map(drop),
    ];

    #[test]
    fn a_one_shot_gives_the_slot_back_when_close_stdin_fails() {
        for one_shot in ONE_SHOTS {
            for (kind, left) in FAILED_WRITES {
                let mut conn = one_slot("shell_v2", &[]);
                conn.transport.fail_write(FIRST_WRITE, kind);
                let mut rx = [0u8; 64];
                let err = one_shot(&mut conn, &mut rx).unwrap_err();
                assert_failed_with(&err, kind, conn.table.in_use(), left);
            }
        }
    }

    #[test]
    fn open_interactive_gives_the_slot_back_when_the_window_size_fails() {
        for (kind, left) in FAILED_WRITES {
            let mut conn = one_slot("shell_v2", &[]);
            conn.transport.fail_write(FIRST_WRITE, kind);
            let mut rx = [0u8; 64];
            let size = Some(WindowSize { rows: 24, cols: 80 });
            let opened = shell_v2::open_interactive(&mut conn, "", None, size, &mut rx);
            let err = now(opened).map(drop).unwrap_err();
            assert_failed_with(&err, kind, conn.table.in_use(), left);
        }
    }
}
