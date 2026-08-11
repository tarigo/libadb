#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::track_app;
use libadb::Error;

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/mod.rs"]
mod common;

// ---------------------------------------------------------------------------
// Tests: track-app (streaming debuggable/profileable process list)
// ---------------------------------------------------------------------------

const TRACK_APP_BANNER: &[u8] = b"device::features=track_app";

fn pb_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn pb_tag(buf: &mut Vec<u8>, field: u64, wire: u64) {
    pb_varint(buf, (field << 3) | wire);
}

fn pb_varint_field(buf: &mut Vec<u8>, field: u64, value: u64) {
    pb_tag(buf, field, 0);
    pb_varint(buf, value);
}

fn pb_bool_field(buf: &mut Vec<u8>, field: u64, value: bool) {
    pb_varint_field(buf, field, value as u64);
}

fn pb_string_field(buf: &mut Vec<u8>, field: u64, data: &[u8]) {
    pb_tag(buf, field, 2);
    pb_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn track_app_entry(
    pid: u64,
    debuggable: bool,
    arch: &[u8],
    process_name: Option<&[u8]>,
    packages: &[&[u8]],
) -> Vec<u8> {
    let mut e = Vec::new();
    pb_varint_field(&mut e, 1, pid);
    pb_bool_field(&mut e, 2, debuggable);
    pb_string_field(&mut e, 4, arch);
    if let Some(name) = process_name {
        pb_string_field(&mut e, 6, name);
    }
    for pkg in packages {
        pb_string_field(&mut e, 7, pkg);
    }
    e
}

fn track_app_snapshot(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = Vec::new();
    for e in entries {
        pb_string_field(&mut msg, 1, e);
    }
    msg
}

fn track_app_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    assert!(
        len <= 0xFFFF,
        "track-app frame length {len} exceeds 4-hex-digit prefix capacity (0xFFFF)",
    );
    let mut out = Vec::with_capacity(4 + len);
    let hex = b"0123456789abcdef";
    out.extend_from_slice(&[
        hex[(len >> 12) & 0xF],
        hex[(len >> 8) & 0xF],
        hex[(len >> 4) & 0xF],
        hex[len & 0xF],
    ]);
    out.extend_from_slice(payload);
    out
}

rt_test! {
async fn track_app_open_yields_first_snapshot() {
    let dev = FakeDevice::new().banner(TRACK_APP_BANNER.to_vec());
    let (mut conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;

        let entry = track_app_entry(
            1234,
            true,
            b"arm64",
            Some(b"com.example.app"),
            &[b"com.example.app"],
        );
        let snapshot = track_app_snapshot(&[entry]);
        ch.send_write(&track_app_frame(&snapshot)).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut tracker = track_app::open(&mut conn, &mut rx).await.unwrap();

    let entries = tracker.read_snapshot().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].pid, 1234);
    assert!(entries[0].debuggable);
    assert_eq!(entries[0].architecture, "arm64");
    assert_eq!(entries[0].process_name.as_deref(), Some("com.example.app"));
    assert_eq!(entries[0].package_names, vec!["com.example.app".to_string()]);

    tracker.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn track_app_streams_multiple_snapshots() {
    let dev = FakeDevice::new().banner(TRACK_APP_BANNER.to_vec());
    let (mut conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;

        let snap1 = track_app_snapshot(&[track_app_entry(
            1,
            false,
            b"arm64",
            Some(b"proc.one"),
            &[],
        )]);
        let snap2 = track_app_snapshot(&[
            track_app_entry(1, false, b"arm64", Some(b"proc.one"), &[]),
            track_app_entry(2, true, b"arm64", Some(b"proc.two"), &[b"pkg.two"]),
        ]);

        let mut combined = Vec::new();
        combined.extend_from_slice(&track_app_frame(&snap1));
        combined.extend_from_slice(&track_app_frame(&snap2));
        ch.send_write(&combined).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut tracker = track_app::open(&mut conn, &mut rx).await.unwrap();

    let first = tracker.read_snapshot().await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].pid, 1);

    let second = tracker.read_snapshot().await.unwrap();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].pid, 1);
    assert_eq!(second[1].pid, 2);
    assert!(second[1].debuggable);
    assert_eq!(second[1].package_names, vec!["pkg.two".to_string()]);

    tracker.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn track_app_empty_snapshot_yields_empty_vec() {
    let dev = FakeDevice::new().banner(TRACK_APP_BANNER.to_vec());
    let (mut conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;

        ch.send_write(&track_app_frame(&[])).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 64];
    let mut tracker = track_app::open(&mut conn, &mut rx).await.unwrap();

    let entries = tracker.read_snapshot().await.unwrap();
    assert!(entries.is_empty());

    tracker.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn track_app_reassembles_snapshot_split_across_writes() {
    let dev = FakeDevice::new().banner(TRACK_APP_BANNER.to_vec());
    let (mut conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;

        let snapshot =
            track_app_snapshot(&[track_app_entry(7, true, b"x86_64", Some(b"frag"), &[])]);
        let frame = track_app_frame(&snapshot);
        let (head, tail) = frame.split_at(3);

        ch.send_write(head).await;
        ch.expect_ack().await;
        ch.send_write(tail).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 256];
    let mut tracker = track_app::open(&mut conn, &mut rx).await.unwrap();

    let entries = tracker.read_snapshot().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].pid, 7);
    assert_eq!(entries[0].architecture, "x86_64");
    assert_eq!(entries[0].process_name.as_deref(), Some("frag"));

    tracker.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn track_app_read_snapshot_after_device_close_returns_channel_closed() {
    let dev = FakeDevice::new().banner(TRACK_APP_BANNER.to_vec());
    let (mut conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;
        ch.send_close().await;
    })
    .await;

    let mut rx = [0u8; 64];
    let mut tracker = track_app::open(&mut conn, &mut rx).await.unwrap();

    let err = tracker.read_snapshot().await.unwrap_err();
    assert!(
        matches!(err, Error::ChannelClosed),
        "expected ChannelClosed, got {err:?}",
    );

    rt::join(device).await;
}
}

rt_test! {
async fn track_app_invalid_hex_length_prefix_surfaces_decode_error() {
    let dev = FakeDevice::new().banner(TRACK_APP_BANNER.to_vec());
    let (mut conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;
        ch.send_write(b"ZZZZ").await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 64];
    let mut tracker = track_app::open(&mut conn, &mut rx).await.unwrap();

    let err = tracker.read_snapshot().await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::Decode(libadb::error::DecodeError::InvalidLengthPrefix),
        ),
        "expected Decode(InvalidLengthPrefix), got {err:?}",
    );

    tracker.close().await.unwrap();
    rt::join(device).await;
}
}
