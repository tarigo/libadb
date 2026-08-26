#![cfg(any(feature = "tokio", feature = "smol"))]

//! The `reverse:` rule service against the fake device, answering in
//! the exact frames a real adbd was probed to send.

use libadb::error::ReverseError;
use libadb::reverse;
use libadb::{Error, ProtocolError};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/common.rs"]
mod common;

rt_test! {
async fn establish_returns_the_service_data() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:forward:tcp:0;tcp:6200\0").await;
        ch.send_write(b"OKAY000538547").await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let data = reverse::establish(&mut conn, "tcp:0", "tcp:6200").await.unwrap();
    assert_eq!(data, b"38547", "the bound port comes back as text");

    rt::join(device).await;
}
}

rt_test! {
async fn establish_surfaces_the_device_failure() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:forward:garbage;tcp:1\0").await;
        ch.send_write(b"FAIL0014bad forward: garbage").await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let err = reverse::establish(&mut conn, "garbage", "tcp:1")
        .await
        .unwrap_err();
    let Error::Reverse(ReverseError::Failed(msg)) = err else {
        panic!("expected Reverse(Failed), got {err:?}");
    };
    assert_eq!(msg, b"bad forward: garbage");

    rt::join(device).await;
}
}

rt_test! {
async fn remove_accepts_the_bare_okay() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:killforward:tcp:6100\0").await;
        ch.send_write(b"OKAY").await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    reverse::remove(&mut conn, "tcp:6100").await.unwrap();

    rt::join(device).await;
}
}

rt_test! {
async fn list_surfaces_the_device_failure() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:list-forward\0").await;
        ch.send_write(b"FAIL000dcannot listen").await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let err = reverse::list(&mut conn).await.unwrap_err();
    let Error::Reverse(ReverseError::Failed(msg)) = err else {
        panic!("expected Reverse(Failed), got {err:?}");
    };
    assert_eq!(msg, b"cannot listen");

    rt::join(device).await;
}
}

rt_test! {
async fn a_reply_flood_is_capped_as_unexpected() {
    // 65 KiB of "listing" — past the 64 KiB reply cap. The client must
    // cut it off with UnexpectedReply and still free the channel.
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:list-forward\0").await;
        for _ in 0..65 {
            ch.send_write(&[b'x'; 1024]).await;
            ch.expect_ack().await;
        }
        ch.expect_close().await;
    })
    .await;

    let err = reverse::list(&mut conn).await.unwrap_err();
    assert!(
        matches!(err, Error::Reverse(ReverseError::UnexpectedReply)),
        "expected UnexpectedReply, got {err:?}"
    );

    rt::join(device).await;
}
}

rt_test! {
async fn a_nul_in_a_spec_never_reaches_the_wire() {
    // The device side expects no traffic at all: every call below must
    // fail before a frame is built.
    let (mut conn, device) =
        session(FakeDevice::new(), b"host::features=", |_s| async move {}).await;

    for err in [
        reverse::establish(&mut conn, "tcp:0\0evil", "tcp:1").await.unwrap_err(),
        reverse::establish(&mut conn, "tcp:0", "tcp:1\0evil").await.unwrap_err(),
        reverse::remove(&mut conn, "tcp:1\0evil").await.unwrap_err(),
    ] {
        assert!(
            matches!(err, Error::Protocol(ProtocolError::InvalidDestination)),
            "expected InvalidDestination, got {err:?}"
        );
    }

    rt::join(device).await;
}
}

rt_test! {
async fn every_call_frees_its_channel_slot() {
    // One round more than there are slots: a call that leaks its slot
    // runs the pool dry before the loop ends.
    const ROUNDS: usize = libadb::connection::DEFAULT_MAX_CHANNELS + 1;

    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        for _ in 0..ROUNDS {
            let mut ch = s.accept_open(b"reverse:killforward:tcp:1\0").await;
            ch.send_write(b"OKAY").await;
            ch.expect_ack().await;
            ch.send_close().await;
            ch.expect_close().await;
        }
    })
    .await;

    for round in 0..ROUNDS {
        rt::timeout_ms(10_000, reverse::remove(&mut conn, "tcp:1"))
            .await
            .unwrap_or_else(|| panic!("round {round} stalled: a slot leaked upstream"))
            .unwrap();
    }

    rt::join(device).await;
}
}

rt_test! {
async fn list_strips_the_length_prefix() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:list-forward\0").await;
        ch.send_write(b"001ahost-19 tcp:6100 tcp:6100\n").await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let listing = reverse::list(&mut conn).await.unwrap();
    assert_eq!(listing, b"host-19 tcp:6100 tcp:6100\n");

    rt::join(device).await;
}
}
