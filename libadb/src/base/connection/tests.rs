//! What a dropped write leaves behind on the wire.

use super::*;
use crate::base::mock::{abandon, connected_with_channel, now};

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
