//! What a dropped write leaves behind on the wire.

use core::future::Future;
use core::task::Poll;

use super::*;
use crate::base::mock::{abandon, connected_for_select, connected_with_channel, now};

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
