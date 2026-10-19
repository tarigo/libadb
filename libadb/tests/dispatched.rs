#![cfg(any(feature = "tokio", feature = "smol"))]

//! Every protocol helper driven over a split connection in dispatched
//! mode: `Reader::run` receives the packets while the helper works the
//! channel through the `Writer`, the way several helpers share one
//! connection at once. Some run inside a spawned task, which only
//! compiles while their futures stay `Send`.
//!
//! `run` acknowledges data as it arrives, so its OKAY and whatever the
//! helper sends after reading that data may reach the device in either
//! order; the device scripts accept both.

use libadb::channel::SelectResult;
use libadb::protocol::command::{CMD_CLSE, CMD_OKAY, CMD_WRTE};
use libadb::shell::{v1 as shell_v1, v2 as shell_v2};
use libadb::{cmd, exec, logcat, reverse, sync, track_app, Error};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/common.rs"]
mod common;
use common::{shell_v2_encode, SH_CLOSE_STDIN, SH_EXIT, SH_STDOUT};

fn logger_entry(pid: i32, tag: &[u8], message: &[u8]) -> Vec<u8> {
    let mut payload = vec![4u8];
    payload.extend_from_slice(tag);
    payload.push(0);
    payload.extend_from_slice(message);
    payload.push(0);
    let mut entry = Vec::new();
    entry.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    entry.extend_from_slice(&28u16.to_le_bytes());
    entry.extend_from_slice(&pid.to_le_bytes());
    entry.extend_from_slice(&[0u8; 20]);
    entry.extend_from_slice(&payload);
    entry
}

rt_test! {
async fn shell_v1_exec_runs_over_the_writer() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell:ls /sdcard\0").await;
        ch.send_write(b"Download\n").await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut buf = [0u8; 64];
    let n = shell_v1::exec(&mut writer, "ls /sdcard", &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"Download\n");
    rt::join(device).await;
}
}

rt_test! {
async fn shell_v2_exec_runs_over_the_writer() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:echo hi\0").await;
        assert_eq!(ch.expect_write_ack().await[0], SH_CLOSE_STDIN);
        let mut reply = shell_v2_encode(SH_STDOUT, b"hi\n");
        reply.extend_from_slice(&shell_v2_encode(SH_EXIT, &[3]));
        ch.send_write(&reply).await;
        ch.expect_unordered([CMD_OKAY, CMD_CLSE]).await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let task = rt::spawn(async move {
        let mut rx = [0u8; 256];
        shell_v2::exec(&mut writer, "echo hi", &mut rx).await.unwrap()
    });
    let out = rt::join(task).await;
    assert_eq!(out.stdout, b"hi\n");
    assert_eq!(out.exit_code, 3);
    rt::join(device).await;
}
}

rt_test! {
async fn logcat_open_reads_entries_over_the_writer() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&shell_v2_encode(SH_STDOUT, &logger_entry(42, b"Tag", b"hello")))
            .await;
        ch.expect_unordered([CMD_OKAY, CMD_CLSE]).await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let task = rt::spawn(async move {
        let mut rx = [0u8; 1024];
        let mut logcat = logcat::open(&mut writer, &[], &mut rx).await.unwrap();
        let entry = logcat.read_entry().await.unwrap();
        logcat.close().await.unwrap();
        entry
    });
    let entry = rt::join(task).await;
    assert_eq!((entry.pid, entry.tag.as_slice()), (42, &b"Tag"[..]));
    assert_eq!(entry.message, b"hello");
    rt::join(device).await;
}
}

rt_test! {
async fn exec_select_reports_the_interrupt_and_then_the_data() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"exec:cat\0").await;
        ch.expect_write_eq(b"ping").await;
        ch.ack(4).await;
        ch.send_write(b"pong").await;
        ch.expect_unordered([CMD_OKAY, CMD_CLSE]).await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut dest = [0u8; 16];
    let mut exec = exec::open(&mut writer, "cat", &mut dest).await.unwrap();
    let mut buf = [0u8; 16];
    let first = exec.select(&mut buf, async {}).await.unwrap();
    assert!(matches!(first, SelectResult::Interrupted(())), "got {first:?}");

    exec.write_stdin(b"ping").await.unwrap();
    let second = rt::timeout_ms(5000, exec.select(&mut buf, core::future::pending::<()>()))
        .await
        .expect("select never saw the data")
        .unwrap();
    let SelectResult::Data(n) = second else {
        panic!("got {second:?}");
    };
    assert_eq!(&buf[..n], b"pong");
    exec.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn exec_run_collects_output_over_the_writer() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"exec:cat /data/file\0").await;
        ch.send_write(b"hello").await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut buf = [0u8; 64];
    let n = exec::run(&mut writer, "cat /data/file", &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    rt::join(device).await;
}
}

rt_test! {
async fn cmd_exec_takes_the_abb_path_over_the_writer() {
    let dev = FakeDevice::new().banner(b"device::features=abb_exec,shell_v2".to_vec());
    let (conn, device) = session(dev, b"host::features=shell_v2,abb_exec", |mut s| async move {
        let mut ch = s.accept_open(b"abb_exec:package\0list\0").await;
        ch.send_write(b"package:a\n").await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut rx = [0u8; 256];
    let out = cmd::exec(&mut writer, &["package", "list"], &mut rx).await.unwrap();
    assert_eq!(out, b"package:a\n");
    rt::join(device).await;
}
}

rt_test! {
async fn sync_stat_runs_over_the_writer() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;
        let req = ch.expect_write_ack().await;
        assert_eq!((&req[..4], &req[8..]), (&b"STAT"[..], &b"/file"[..]));
        let mut body = [0u8; 16];
        body[0..4].copy_from_slice(b"STAT");
        body[4..8].copy_from_slice(&0o100644u32.to_le_bytes());
        body[8..12].copy_from_slice(&42u32.to_le_bytes());
        ch.send_write(&body).await;
        let [_, quit] = ch.expect_unordered([CMD_OKAY, CMD_WRTE]).await;
        assert_eq!(&quit[..4], b"QUIT");
        ch.ack(quit.len() as u32).await;
        ch.expect_close().await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut buf = [0u8; 128];
    let mut sync = sync::open(&mut writer, &mut buf).await.unwrap();
    let stat = sync.stat("/file").await.unwrap();
    assert_eq!((stat.mode, stat.size), (0o100644, 42));
    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn track_app_reads_a_snapshot_over_the_writer() {
    let dev = FakeDevice::new().banner(b"device::features=track_app".to_vec());
    let (conn, device) = session(dev, b"host::features=track_app", |mut s| async move {
        let mut ch = s.accept_open(b"track-app\0").await;
        ch.send_write(b"0000").await;
        ch.expect_unordered([CMD_OKAY, CMD_CLSE]).await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut rx = [0u8; 256];
    let mut tracker = track_app::open(&mut writer, &mut rx).await.unwrap();
    assert!(tracker.read_snapshot().await.unwrap().is_empty());
    tracker.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn reverse_establish_runs_over_the_writer() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"reverse:forward:tcp:0;tcp:6200\0").await;
        ch.send_write(b"OKAY000538547").await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let data = reverse::establish(&mut writer, "tcp:0", "tcp:6200").await.unwrap();
    assert_eq!(data, b"38547");
    rt::join(device).await;
}
}

rt_test! {
async fn a_helper_fails_with_disconnected_once_reception_ends() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=", |_s| async move {})
        .await;
    let (reader, mut writer) = conn.split().unwrap();
    rt::join(device).await;
    rt::join(rt::spawn(reader.run())).await.unwrap_err();

    let mut buf = [0u8; 16];
    let err = exec::run(&mut writer, "true", &mut buf).await.unwrap_err();
    assert!(matches!(err, Error::Disconnected), "got {err:?}");
}
}
