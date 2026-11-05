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
use libadb::{cmd, exec, logcat, reverse, sync, track_app, ConnectionConfig, Error};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, session_with_config, FakeDevice};

#[path = "common/common.rs"]
mod common;
use common::{logger_entry, logger_payload, shell_v2_encode, SH_CLOSE_STDIN, SH_EXIT, SH_STDOUT};

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

// A command may finish before its task reaches `close_stdin`: `run` has
// taken the output and the CLSE by then. Stdin is gone, which is no
// failure, so the output still comes back and the slot is freed as
// usual. `marker` fixes that order: its data follows the CLSE, and `run`
// dispatches packets in order. It also holds one of the two slots, so
// the last open can only get the one the shell gave back. With delayed
// ACK every OKAY leaves from the read that took the data, which puts the
// host's packets in one order for the device to expect.
rt_test! {
async fn close_stdin_finds_the_channel_already_closed() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2,delayed_ack".to_vec()).delayed_ack(4096);
    let config = ConnectionConfig::new().with_max_channels(2);
    let (conn, device) = session_with_config(dev, b"host::features=shell_v2,delayed_ack", config, |mut s| async move {
        let (marker_dev, marker_cli) = {
            let ch = s.accept_open(b"marker:\0").await;
            (ch.device_id(), ch.client_id())
        };
        let mut shell = s.accept_open(b"shell,v2,raw:echo hi\0").await;
        let (shell_dev, shell_cli) = (shell.device_id(), shell.client_id());
        let mut reply = shell_v2_encode(SH_STDOUT, b"hi\n");
        reply.extend_from_slice(&shell_v2_encode(SH_EXIT, &[3]));
        shell.send_write(&reply).await;
        shell.send_close().await;
        s.send(CMD_WRTE, marker_dev, marker_cli, b"go").await;

        let (okay, _) = s.expect(CMD_OKAY).await;
        assert_eq!((okay.arg0, okay.arg1), (marker_cli, marker_dev));
        let (okay, _) = s.expect(CMD_OKAY).await;
        assert_eq!((okay.arg0, okay.arg1), (shell_cli, shell_dev));
        let (close, _) = s.expect(CMD_CLSE).await;
        assert_eq!((close.arg0, close.arg1), (shell_cli, shell_dev));
        s.accept_open(b"again:\0").await;
        s
    })
    .await;
    let (reader, writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let marker = writer.open_channel(b"marker:\0").await.unwrap();
    let mut shell_writer = writer.clone();
    let mut rx = [0u8; 256];
    let mut shell = shell_v2::open(&mut shell_writer, "echo hi", &mut rx).await.unwrap();
    let mut buf = [0u8; 8];
    let n = rt::within("the read on marker", writer.read_channel(marker, &mut buf)).await.unwrap();
    assert_eq!(&buf[..n], b"go");

    shell.close_stdin().await.unwrap();
    let out = rt::within("collect", shell.collect()).await.unwrap();
    assert_eq!(out.stdout, b"hi\n");
    assert_eq!(out.exit_code, 3);

    writer.open_channel(b"again:\0").await.unwrap();
    rt::within("the device", rt::join(device)).await;
}
}

// Only the device closing the channel passes: a channel `run` closed
// because the device wrote past its receive cap still fails with that.
rt_test! {
async fn close_stdin_still_fails_on_a_channel_a_fault_closed() {
    const CHUNK: usize = 4096;
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let config = ConnectionConfig::new()
        .with_max_payload(CHUNK as u32)
        .with_max_rx_per_channel(CHUNK);
    let (conn, device) = session_with_config(dev, b"host::features=shell_v2", config, |mut s| async move {
        let (marker_dev, marker_cli) = {
            let ch = s.accept_open(b"marker:\0").await;
            (ch.device_id(), ch.client_id())
        };
        let (shell_dev, shell_cli) = {
            let ch = s.accept_open(b"shell,v2,raw:echo hi\0").await;
            (ch.device_id(), ch.client_id())
        };
        for _ in 0..2 {
            s.send(CMD_WRTE, shell_dev, shell_cli, &[0xEE; CHUNK]).await;
        }
        s.send(CMD_WRTE, marker_dev, marker_cli, b"go").await;

        // The first chunk fills the buffer, so its OKAY waits for a read
        // that never comes; the second does not fit, and `run` sends the
        // CLSE for it before it even looks at `marker`'s data.
        let (close, _) = s.expect(CMD_CLSE).await;
        assert_eq!((close.arg0, close.arg1), (shell_cli, shell_dev));
        let (okay, _) = s.expect(CMD_OKAY).await;
        assert_eq!((okay.arg0, okay.arg1), (marker_cli, marker_dev));
        s
    })
    .await;
    let (reader, writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let marker = writer.open_channel(b"marker:\0").await.unwrap();
    let mut shell_writer = writer.clone();
    let mut rx = [0u8; 256];
    let mut shell = shell_v2::open(&mut shell_writer, "echo hi", &mut rx).await.unwrap();
    let mut buf = [0u8; 8];
    let n = rt::within("the read on marker", writer.read_channel(marker, &mut buf)).await.unwrap();
    assert_eq!(&buf[..n], b"go");

    let err = shell.close_stdin().await.unwrap_err();
    assert!(matches!(err, Error::ChannelRxOverflow), "got {err:?}");
    rt::within("the device", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_open_reads_entries_over_the_writer() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&shell_v2_encode(SH_STDOUT, &logger_entry(42, 0, 0, 0, 0, 0, &logger_payload(4, b"Tag", b"hello"))))
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
async fn exec_exec_collects_output_over_the_writer() {
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
    let n = exec::exec(&mut writer, "cat /data/file", &mut buf).await.unwrap();
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
        ch.expect_close().await;
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut rx = [0u8; 256];
    let out = cmd::exec(&mut writer, &["package", "list"], &mut rx).await.unwrap();
    assert_eq!(out, b"package:a\n");
    rt::within("the device waiting for our CLSE", rt::join(device)).await;
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
        let [_, quit, _] = ch.expect_unordered([CMD_OKAY, CMD_WRTE, CMD_CLSE]).await;
        assert_eq!(&quit[..4], b"QUIT");
    })
    .await;
    let (reader, mut writer) = conn.split().unwrap();
    let _driver = rt::spawn(reader.run());

    let mut buf = [0u8; 128];
    let mut sync = sync::open(&mut writer, &mut buf).await.unwrap();
    let stat = sync.stat("/file").await.unwrap();
    assert_eq!((stat.mode, stat.size), (sync::FileMode(0o100644), 42));
    sync.quit().await.unwrap();
    rt::within("the device", rt::join(device)).await;
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

    let port = reverse::establish(&mut writer, "tcp:0", "tcp:6200").await.unwrap();
    assert_eq!(port, Some(38547));
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
    let err = exec::exec(&mut writer, "true", &mut buf).await.unwrap_err();
    assert!(matches!(err, Error::Disconnected), "got {err:?}");
}
}
