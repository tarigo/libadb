#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::logcat;
use libadb::Error;

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/common.rs"]
mod common;
use common::{shell_v2_encode, SH_CLOSE_STDIN, SH_EXIT, SH_STDOUT};

// ---------------------------------------------------------------------------
// Tests: logcat (binary and text modes)
// ---------------------------------------------------------------------------

/// Build a v4 `logger_entry` record: 28-byte header + caller-supplied
/// payload.
fn logger_entry(
    pid: i32,
    tid: u32,
    sec: i32,
    nsec: i32,
    lid: u32,
    uid: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(28 + payload.len());
    buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    buf.extend_from_slice(&28u16.to_le_bytes());
    buf.extend_from_slice(&pid.to_le_bytes());
    buf.extend_from_slice(&tid.to_le_bytes());
    buf.extend_from_slice(&sec.to_le_bytes());
    buf.extend_from_slice(&nsec.to_le_bytes());
    buf.extend_from_slice(&lid.to_le_bytes());
    buf.extend_from_slice(&uid.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Build a `[priority][tag\0][message\0]` logcat payload.
fn logger_payload(priority: u8, tag: &[u8], message: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + tag.len() + 1 + message.len() + 1);
    p.push(priority);
    p.extend_from_slice(tag);
    p.push(0);
    p.extend_from_slice(message);
    p.push(0);
    p
}

rt_test! {
async fn logcat_open_yields_parsed_entries() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;

        let e1 = logger_entry(111, 222, 100, 0, 0, 1000, &logger_payload(4, b"TagA", b"first"));
        let e2 = logger_entry(333, 444, 101, 0, 3, 1001, &logger_payload(5, b"TagB", b"second"));

        ch.send_write(&shell_v2_encode(SH_STDOUT, &e1)).await;
        ch.expect_ack().await;
        ch.send_write(&shell_v2_encode(SH_STDOUT, &e2)).await;
        ch.expect_ack().await;
        ch.send_write(&shell_v2_encode(SH_EXIT, &[0])).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut logcat = logcat::open(&mut conn, &[], &mut rx).await.unwrap();

    let entry = logcat.read_entry().await.unwrap();
    assert_eq!(entry.pid, 111);
    assert_eq!(entry.tag, b"TagA");
    assert_eq!(entry.message, b"first");
    assert_eq!(entry.priority, logcat::Priority::Info);
    assert_eq!(entry.log_id, logcat::LogId::Main);

    let entry = logcat.read_entry().await.unwrap();
    assert_eq!(entry.pid, 333);
    assert_eq!(entry.tag, b"TagB");
    assert_eq!(entry.message, b"second");
    assert_eq!(entry.priority, logcat::Priority::Warn);
    assert_eq!(entry.log_id, logcat::LogId::System);

    let err = logcat.read_entry().await.unwrap_err();
    assert!(matches!(err, Error::ChannelClosed));

    logcat.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn logcat_dump_collects_until_exit() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s
            .accept_open(b"shell,v2,raw:logcat -B -d -b crash\0")
            .await;

        let entry = logger_entry(7, 7, 200, 0, 4, 0, &logger_payload(6, b"CrashTag", b"boom"));
        let mut combined = Vec::new();
        combined.extend_from_slice(&shell_v2_encode(SH_STDOUT, &entry));
        combined.extend_from_slice(&shell_v2_encode(SH_EXIT, &[0]));
        ch.send_write(&combined).await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let entries = logcat::dump(&mut conn, &["-b", "crash"], &mut rx).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag, b"CrashTag");
    assert_eq!(entries[0].message, b"boom");
    assert_eq!(entries[0].priority, logcat::Priority::Error);
    assert_eq!(entries[0].log_id, logcat::LogId::Crash);

    rt::join(device).await;
}
}

rt_test! {
async fn logcat_exec_text_collects_stdout_and_exit_code() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s
            .accept_open(b"shell,v2,raw:logcat -d -v threadtime\0")
            .await;

        let close_stdin = ch.expect_write_ack().await;
        assert_eq!(close_stdin[0], SH_CLOSE_STDIN);

        let mut combined = Vec::new();
        combined.extend_from_slice(&shell_v2_encode(SH_STDOUT, b"01-01 12:00:00 I TagA: first\n"));
        combined.extend_from_slice(&shell_v2_encode(SH_EXIT, &[0]));
        ch.send_write(&combined).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let out = logcat::exec_text(&mut conn, &["-d", "-v", "threadtime"], &mut rx)
        .await
        .unwrap();
    assert_eq!(out.stdout, b"01-01 12:00:00 I TagA: first\n");
    assert_eq!(out.exit_code, 0);

    rt::join(device).await;
}
}

rt_test! {
async fn logcat_open_text_exposes_raw_shell_v2_frames() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -s MyTag:D\0").await;

        ch.send_write(&shell_v2_encode(SH_STDOUT, b"line\n")).await;
        ch.expect_ack().await;
        ch.send_write(&shell_v2_encode(SH_EXIT, &[0])).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let shell = logcat::open_text(&mut conn, &["-s", "MyTag:D"], &mut rx)
        .await
        .unwrap();

    let out = shell.collect().await.unwrap();
    assert_eq!(out.stdout, b"line\n");
    assert_eq!(out.exit_code, 0);

    rt::join(device).await;
}
}
