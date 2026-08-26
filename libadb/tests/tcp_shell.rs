#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::shell::v1 as shell_v1;
use libadb::Error;

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/common.rs"]
mod common;
use common::{shell_v2_encode, shell_v2_parse, SH_CLOSE_STDIN, SH_EXIT, SH_STDERR, SH_STDOUT};

// ---------------------------------------------------------------------------
// Shell v2 framing test
// ---------------------------------------------------------------------------

/// Fill `buf` in full from `ch`, propagating only `ChannelClosed` as EOF.
///
/// `Channel::read` can legitimately return `Ok(0)` for an empty WRTE
/// frame — that's "no progress", not EOF. Real end-of-stream surfaces
/// as `Err(ChannelClosed)` and triggers a panic here.
async fn read_exact_or_panic(
    ch: &mut libadb::channel::Channel<'_, rt::AdbTransport>,
    buf: &mut [u8],
) {
    let mut pos = 0;
    while pos < buf.len() {
        match ch.read(&mut buf[pos..]).await {
            Ok(n) => pos += n,
            Err(libadb::Error::ChannelClosed) => {
                panic!("channel closed with {} bytes unread", buf.len() - pos)
            }
            Err(e) => panic!("read error with {} bytes unread: {e:?}", buf.len() - pos),
        }
    }
}

async fn read_shell_v2_frame(
    ch: &mut libadb::channel::Channel<'_, rt::AdbTransport>,
    buf: &mut [u8],
) -> (u8, usize) {
    let mut hdr5 = [0u8; 5];
    read_exact_or_panic(ch, &mut hdr5).await;
    let (id, length) = shell_v2_parse(&hdr5);
    let length = length as usize;
    assert!(
        length <= buf.len(),
        "shell_v2 frame payload {} exceeds test buffer {}",
        length,
        buf.len(),
    );
    read_exact_or_panic(ch, &mut buf[..length]).await;
    (id, length)
}

rt_test! {
async fn shell_v2_session() {
    let (mut conn, device) = session(
        FakeDevice::new(),
        b"host::features=shell_v2",
        |mut s| async move {
            let (mut ch, dest) = s.accept_open_any().await;
            assert!(dest.starts_with(b"shell,v2,raw:"));

            let payload = ch.expect_write_ack().await;
            let hdr5: [u8; 5] = payload[..5].try_into().unwrap();
            let (id, len) = shell_v2_parse(&hdr5);
            assert_eq!(id, SH_CLOSE_STDIN);
            assert_eq!(len, 0);

            ch.send_write(&shell_v2_encode(SH_STDOUT, b"hello stdout\n"))
                .await;
            ch.expect_ack().await;
            ch.send_write(&shell_v2_encode(SH_STDERR, b"a warning\n"))
                .await;
            ch.expect_ack().await;
            ch.send_write(&shell_v2_encode(SH_EXIT, &[42])).await;
            ch.expect_ack().await;

            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"shell,v2,raw:echo test\0").await.unwrap();

    let close_stdin = shell_v2_encode(SH_CLOSE_STDIN, &[]);
    ch.write(&close_stdin).await.unwrap();

    let mut collected_stdout = Vec::new();
    let mut collected_stderr = Vec::new();
    let mut exit_code: Option<u8> = None;
    let mut buf = [0u8; 4096];

    while exit_code.is_none() {
        let (id, length) = read_shell_v2_frame(&mut ch, &mut buf).await;
        match id {
            SH_STDOUT => collected_stdout.extend_from_slice(&buf[..length]),
            SH_STDERR => collected_stderr.extend_from_slice(&buf[..length]),
            SH_EXIT => exit_code = Some(if length > 0 { buf[0] } else { 0 }),
            _ => {}
        }
    }

    assert_eq!(collected_stdout, b"hello stdout\n");
    assert_eq!(collected_stderr, b"a warning\n");
    assert_eq!(exit_code, Some(42));

    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn shell_v2_combined_packets() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:test\0").await;

        let mut combined = Vec::new();
        combined.extend_from_slice(&shell_v2_encode(SH_STDOUT, b"line1\n"));
        combined.extend_from_slice(&shell_v2_encode(SH_STDERR, b"err\n"));
        combined.extend_from_slice(&shell_v2_encode(SH_STDOUT, b"line2\n"));
        combined.extend_from_slice(&shell_v2_encode(SH_EXIT, &[0]));

        ch.send_write(&combined).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut ch = conn.open(b"shell,v2,raw:test\0").await.unwrap();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: Option<u8> = None;
    let mut buf = [0u8; 4096];

    while exit_code.is_none() {
        let (id, length) = read_shell_v2_frame(&mut ch, &mut buf).await;
        match id {
            SH_STDOUT => stdout.extend_from_slice(&buf[..length]),
            SH_STDERR => stderr.extend_from_slice(&buf[..length]),
            SH_EXIT => exit_code = Some(if length > 0 { buf[0] } else { 0 }),
            _ => {}
        }
    }

    assert_eq!(stdout, b"line1\nline2\n");
    assert_eq!(stderr, b"err\n");
    assert_eq!(exit_code, Some(0));

    ch.close().await.unwrap();
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Tests: shell_v1 (legacy) session
// ---------------------------------------------------------------------------

rt_test! {
async fn shell_v1_exec_collects_output_until_channel_close() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell:ls /sdcard\0").await;
        ch.send_write(b"Download\n").await;
        ch.expect_ack().await;
        ch.send_write(b"Pictures\n").await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;

    let mut buf = [0u8; 128];
    let n = shell_v1::exec(&mut conn, "ls /sdcard", &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"Download\nPictures\n");

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v1_exec_with_empty_command_opens_default_shell() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell:\0").await;
        ch.send_close().await;
    })
    .await;

    let mut buf = [0u8; 64];
    let n = shell_v1::exec(&mut conn, "", &mut buf).await.unwrap();
    assert_eq!(n, 0);

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v1_exec_returns_buffer_full_when_output_exceeds_capacity() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell:yes\0").await;
        ch.send_write(&[b'y'; 16]).await;
        ch.expect_ack().await;
        ch.send_write(&[b'y'; 16]).await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;

    let mut buf = [0u8; 32];
    let err = shell_v1::exec(&mut conn, "yes", &mut buf).await.unwrap_err();
    assert!(matches!(err, Error::ReceiveBufferFull));

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v1_open_streams_output_and_forwards_stdin() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell:\0").await;

        ch.send_write(b"$ ").await;
        ch.expect_ack().await;

        let stdin = ch.expect_write_ack().await;
        assert_eq!(&stdin, b"echo hi\n");

        ch.send_write(b"hi\n$ ").await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut dest_buf = [0u8; 16];
    let mut shell = shell_v1::open(&mut conn, "", &mut dest_buf).await.unwrap();

    let mut buf = [0u8; 32];
    let n = shell.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"$ ");

    shell.write_stdin(b"echo hi\n").await.unwrap();

    let mut collected = Vec::new();
    while collected != b"hi\n$ " {
        let n = shell.read(&mut buf).await.unwrap();
        collected.extend_from_slice(&buf[..n]);
    }

    shell.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn shell_v1_read_reports_channel_closed_when_device_closes() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell:exit\0").await;
        ch.send_close().await;
    })
    .await;

    let mut dest_buf = [0u8; 32];
    let mut shell = shell_v1::open(&mut conn, "exit", &mut dest_buf).await.unwrap();

    let mut buf = [0u8; 32];
    let err = shell.read(&mut buf).await.unwrap_err();
    assert!(matches!(err, Error::ChannelClosed));

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v1_open_with_tight_dest_buffer_fails_cleanly() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        if rt::timeout_ms(100, s.recv()).await.is_some() {
            panic!("client sent OPEN despite dest buffer overflow");
        }
    })
    .await;

    let mut dest_buf = [0u8; 4];
    let Err(err) = shell_v1::open(&mut conn, "ls", &mut dest_buf).await else {
        panic!("expected Err(ReceiveBufferFull)");
    };
    assert!(matches!(err, Error::ReceiveBufferFull));

    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
