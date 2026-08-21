#![cfg(any(feature = "tokio", feature = "smol"))]

//! Checksum policy.
//!
//! ADB dropped payload checksums in protocol version `0x0100_0001`:
//! both peers agree on `min(mine, theirs)` during the CNXN exchange and,
//! from then on, a sender that is at or above that version writes
//! `data_check = 0`. Computing the sum anyway costs a full pass over
//! every outgoing payload — measurably so on a microcontroller.
//!
//! Until the device has introduced itself its version is unknown, so
//! handshake packets keep carrying a real checksum: a pre-2017 device
//! would otherwise reject our CNXN outright.

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, AuthPolicy, FakeDevice, TEST_SIGNATURE};

#[path = "common/mod.rs"]
mod common;

use libadb::protocol::constant::{ADB_VERSION, ADB_VERSION_SKIP_CHECKSUM};
use libadb::Error;

const LEGACY_VERSION: u32 = 0x0100_0000;
const HOST_BANNER: &[u8] = b"host::features=shell_v2";

fn sum(payload: &[u8]) -> u32 {
    payload
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

// ---------------------------------------------------------------------------
// Version negotiation
// ---------------------------------------------------------------------------

rt_test! {
async fn protocol_version_is_the_minimum_of_both_sides() {
    // Device newer than us: we cap at what this library implements.
    let (conn, device) = session(
        FakeDevice::new().protocol_version(0x0100_0009),
        HOST_BANNER,
        |s| async move { s },
    )
    .await;
    assert_eq!(conn.protocol_version(), ADB_VERSION);
    let s = rt::join(device).await;
    assert_eq!(s.host_protocol_version(), ADB_VERSION);

    // Device older than us: we drop to its version.
    let (conn, device) = session(
        FakeDevice::new().protocol_version(LEGACY_VERSION),
        HOST_BANNER,
        |s| async move { s },
    )
    .await;
    assert_eq!(conn.protocol_version(), LEGACY_VERSION);
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Handshake packets: version still unknown, so keep the checksum
// ---------------------------------------------------------------------------

rt_test! {
async fn handshake_packets_carry_a_checksum() {
    let (_conn, device) = session(
        FakeDevice::new().auth(AuthPolicy::AcceptSignature {
            token: b"token-bytes".to_vec(),
        }),
        HOST_BANNER,
        |s| async move { s },
    )
    .await;

    let s = rt::join(device).await;
    let headers = s.handshake_headers();
    assert_eq!(headers.len(), 2, "expected CNXN + AUTH(SIGNATURE)");

    assert_eq!(
        headers[0].data_check,
        sum(HOST_BANNER),
        "the host's CNXN must be checksummed: the device has not told us \
         its version yet, and a v1 device would reject an unchecked packet",
    );
    assert_eq!(
        headers[1].data_check,
        sum(TEST_SIGNATURE),
        "AUTH also predates version negotiation",
    );
}
}

// ---------------------------------------------------------------------------
// After the handshake
// ---------------------------------------------------------------------------

rt_test! {
async fn writes_skip_the_checksum_with_a_modern_device() {
    let payload = b"payload that must not be summed";

    let (mut conn, device) = session(
        FakeDevice::new().protocol_version(ADB_VERSION_SKIP_CHECKSUM),
        HOST_BANNER,
        |mut s| async move {
            let (mut ch, _) = s.accept_open_any().await;
            let (hdr, data) = ch.recv_any().await;
            assert_eq!(data, b"payload that must not be summed");
            assert_eq!(hdr.data_check, 0, "WRTE must go out unchecked");
            ch.ack(data.len() as u32).await;
            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    ch.write(payload).await.unwrap();
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn writes_carry_a_checksum_with_a_legacy_device() {
    let payload = b"legacy peers still verify this";

    let (mut conn, device) = session(
        FakeDevice::new().protocol_version(LEGACY_VERSION),
        HOST_BANNER,
        |mut s| async move {
            let (mut ch, _) = s.accept_open_any().await;
            let (hdr, data) = ch.recv_any().await;
            assert_eq!(
                hdr.data_check,
                sum(&data),
                "a v1 device verifies the sum, so it must be present"
            );
            ch.ack(data.len() as u32).await;
            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    ch.write(payload).await.unwrap();
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn okay_replies_skip_the_checksum_with_a_modern_device() {
    // Delayed-ACK OKAYs carry a 4-byte payload, so they are the one
    // control packet where the policy is observable.
    let (mut conn, device) = session(
        FakeDevice::new()
            .banner(b"device::features=shell_v2,delayed_ack")
            .protocol_version(ADB_VERSION_SKIP_CHECKSUM)
            .delayed_ack(4096),
        b"host::features=shell_v2,delayed_ack",
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;
            ch.send_write(b"hello").await;
            let (hdr, payload) = ch.recv_any().await;
            assert_eq!(payload.len(), 4, "delayed-ack OKAY carries a credit");
            assert_eq!(hdr.data_check, 0, "OKAY must go out unchecked too");
            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    let mut buf = [0u8; 32];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Receive path is unchanged: a checksum that is present must be right
// ---------------------------------------------------------------------------

rt_test! {
async fn inbound_wrong_checksum_is_still_rejected() {
    let (mut conn, device) = session(
        FakeDevice::new().protocol_version(LEGACY_VERSION),
        HOST_BANNER,
        |mut s| async move {
            let (ch, _) = s.accept_open_any().await;
            let (dev, cli) = (ch.device_id(), ch.client_id());
            // Hand-rolled WRTE with a deliberately wrong data_check.
            let payload = b"corrupted";
            let mut hdr = [0u8; 24];
            let cmd = libadb::protocol::command::CMD_WRTE;
            hdr[0..4].copy_from_slice(&cmd.to_le_bytes());
            hdr[4..8].copy_from_slice(&dev.to_le_bytes());
            hdr[8..12].copy_from_slice(&cli.to_le_bytes());
            hdr[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            hdr[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
            hdr[20..24].copy_from_slice(&(cmd ^ 0xFFFF_FFFF).to_le_bytes());
            s.send_raw_bytes(&hdr).await;
            s.send_raw_bytes(payload).await;
            s
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    let mut buf = [0u8; 64];
    let err = ch.read(&mut buf).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol(libadb::ProtocolError::InvalidChecksum)
        ),
        "expected InvalidChecksum, got {err:?}"
    );
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// The split Writer follows the same policy
// ---------------------------------------------------------------------------

rt_test! {
async fn split_writer_skips_the_checksum_with_a_modern_device() {
    let (conn, device) = session(
        FakeDevice::new().protocol_version(ADB_VERSION_SKIP_CHECKSUM),
        HOST_BANNER,
        |mut s| async move {
            let (mut ch, _) = s.accept_open_any().await;
            let (hdr, data) = ch.recv_any().await;
            assert_eq!(data, b"through the split writer");
            assert_eq!(hdr.data_check, 0);
            ch.ack(data.len() as u32).await;
            s
        },
    )
    .await;

    assert_eq!(conn.protocol_version(), ADB_VERSION_SKIP_CHECKSUM);
    let (mut reader, writer) = conn.split().unwrap();
    assert_eq!(reader.protocol_version(), ADB_VERSION_SKIP_CHECKSUM);
    assert_eq!(writer.protocol_version(), ADB_VERSION_SKIP_CHECKSUM);

    let ch = reader.open_channel(b"svc:\0").await.unwrap();
    writer
        .write_channel(ch, b"through the split writer")
        .await
        .unwrap();
    rt::join(device).await;
}
}
