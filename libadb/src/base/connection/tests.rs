//! What a dropped write leaves behind on the wire.

use alloc::vec;
use core::future::Future;
use core::task::Poll;

use super::*;
use crate::base::mock::{
    abandon, connected_for_select, connected_with_channel, now, two_channels_classic,
    two_channels_delayed_ack, wrte,
};

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
