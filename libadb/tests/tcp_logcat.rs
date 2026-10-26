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
use common::{
    logger_entry, logger_payload, shell_v2_encode, SH_CLOSE_STDIN, SH_EXIT, SH_STDERR, SH_STDOUT,
};

// ---------------------------------------------------------------------------
// Tests: logcat (binary and text modes)
// ---------------------------------------------------------------------------

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
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let entries = logcat::dump(&mut conn, &["-b", "crash"], &mut rx).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag, b"CrashTag");
    assert_eq!(entries[0].message, b"boom");
    assert_eq!(entries[0].priority, logcat::Priority::Error);
    assert_eq!(entries[0].log_id, logcat::LogId::Crash);

    rt::within("the device waiting for our CLSE", rt::join(device)).await;
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

/// `n` main-buffer entries of 100 bytes each, back to back.
fn hundred_byte_entries(n: usize) -> Vec<u8> {
    let message = [b'x'; 100 - 28 - 1 - 4 - 1];
    (0..n as i32)
        .flat_map(|pid| logger_entry(pid, 0, 0, 0, 0, 0, &logger_payload(4, b"Tag", &message)))
        .collect()
}

rt_test! {
async fn logcat_reads_a_frame_larger_than_its_buffer() {
    let stdout = hundred_byte_entries(15);
    let mut wire = shell_v2_encode(SH_STDOUT, &stdout);
    wire.extend_from_slice(&shell_v2_encode(SH_EXIT, &[0]));
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut logcat = logcat::open(&mut conn, &[], &mut rx).await.unwrap();
    for pid in 0..15 {
        assert_eq!(logcat.read_entry().await.unwrap().pid, pid);
    }
    assert!(matches!(logcat.read_entry().await, Err(Error::ChannelClosed)));

    logcat.close().await.unwrap();
    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_skips_a_stderr_frame_larger_than_its_buffer() {
    let mut wire = shell_v2_encode(SH_STDERR, &[b'e'; 2000]);
    wire.extend_from_slice(&shell_v2_encode(SH_STDOUT, &hundred_byte_entries(1)));
    wire.extend_from_slice(&shell_v2_encode(SH_EXIT, &[0]));
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut logcat = logcat::open(&mut conn, &[], &mut rx).await.unwrap();
    assert_eq!(logcat.read_entry().await.unwrap().pid, 0);
    assert!(matches!(logcat.read_entry().await, Err(Error::ChannelClosed)));

    logcat.close().await.unwrap();
    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_yields_the_entries_that_arrived_before_a_frame_was_cut() {
    // The frame promises three entries; the channel closes after two
    // and a half of them.
    let wire = shell_v2_encode(SH_STDOUT, &hundred_byte_entries(3));
    let cut = wire[..5 + 250].to_vec();
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&cut).await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut logcat = logcat::open(&mut conn, &[], &mut rx).await.unwrap();
    assert_eq!(logcat.read_entry().await.unwrap().pid, 0);
    assert_eq!(logcat.read_entry().await.unwrap().pid, 1);
    let err = logcat.read_entry().await.unwrap_err();
    assert!(
        matches!(err, Error::Logcat(logcat::LogcatError::ClosedWithoutExit)),
        "got {err:?}"
    );

    logcat.close().await.unwrap();
    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_dump_frees_the_slot_when_it_fails() {
    let mut bad = logger_entry(1, 1, 0, 0, 0, 0, b"x");
    bad[2..4].copy_from_slice(&4u16.to_le_bytes());
    let wire = shell_v2_encode(SH_STDOUT, &bad);
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B -d\0").await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let err = logcat::dump(&mut conn, &[], &mut rx).await.unwrap_err();
    assert!(
        matches!(err, Error::Logcat(logcat::LogcatError::InvalidHeader)),
        "got {err:?}"
    );

    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_dump_fails_when_logcat_exits_with_an_error() {
    let mut wire = shell_v2_encode(SH_STDERR, b"logcat: Unknown -b buffer 'nosuch'.\n");
    wire.extend_from_slice(&shell_v2_encode(SH_EXIT, &[1]));
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s
            .accept_open(b"shell,v2,raw:logcat -B -d -b nosuch\0")
            .await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let err = logcat::dump(&mut conn, &["-b", "nosuch"], &mut rx)
        .await
        .unwrap_err();
    let Error::Logcat(logcat::LogcatError::Exited { code, stderr }) = &err else {
        panic!("got {err:?}");
    };
    assert_eq!(*code, 1);
    assert_eq!(stderr, b"logcat: Unknown -b buffer 'nosuch'.\n");
    assert_eq!(
        err.to_string(),
        "logcat exited with status 1: logcat: Unknown -b buffer 'nosuch'."
    );

    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_yields_its_entries_before_the_status_it_failed_with() {
    let mut wire = shell_v2_encode(SH_STDOUT, &hundred_byte_entries(2));
    wire.extend_from_slice(&shell_v2_encode(SH_STDERR, b"logcat: Unexpected EOF!\n"));
    wire.extend_from_slice(&shell_v2_encode(SH_EXIT, &[1]));
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut logcat = logcat::open(&mut conn, &[], &mut rx).await.unwrap();
    assert_eq!(logcat.read_entry().await.unwrap().pid, 0);
    assert_eq!(logcat.read_entry().await.unwrap().pid, 1);
    for _ in 0..2 {
        let err = logcat.read_entry().await.unwrap_err();
        assert!(
            matches!(err, Error::Logcat(logcat::LogcatError::Exited { code: 1, .. })),
            "got {err:?}"
        );
    }

    logcat.close().await.unwrap();
    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_fails_a_stream_that_closes_without_an_exit_status() {
    let wire = shell_v2_encode(SH_STDOUT, &hundred_byte_entries(2));
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B\0").await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let mut logcat = logcat::open(&mut conn, &[], &mut rx).await.unwrap();
    assert_eq!(logcat.read_entry().await.unwrap().pid, 0);
    assert_eq!(logcat.read_entry().await.unwrap().pid, 1);
    for _ in 0..2 {
        let err = logcat.read_entry().await.unwrap_err();
        assert!(
            matches!(err, Error::Logcat(logcat::LogcatError::ClosedWithoutExit)),
            "got {err:?}"
        );
    }

    logcat.close().await.unwrap();
    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}

rt_test! {
async fn logcat_dump_fails_when_the_stream_closes_without_an_exit_status() {
    let wire = shell_v2_encode(SH_STDOUT, &hundred_byte_entries(2));
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:logcat -B -d\0").await;
        ch.send_write(&wire).await;
        ch.expect_ack().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let err = logcat::dump(&mut conn, &[], &mut rx).await.unwrap_err();
    assert!(
        matches!(err, Error::Logcat(logcat::LogcatError::ClosedWithoutExit)),
        "got {err:?}"
    );

    rt::within("the device waiting for our CLSE", rt::join(device)).await;
}
}
