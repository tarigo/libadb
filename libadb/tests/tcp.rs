#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::protocol::command::{CMD_CLSE, CMD_OKAY, CMD_OPEN, CMD_WRTE};
use libadb::shell::v2 as shell_v2;
use libadb::{abb, cmd, exec, logcat, track_app, Connection, Error, Feature};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{
    session, wrap, AuthPolicy, FakeDevice, TestAuth, DEFAULT_BANNER, DEFAULT_MAX_PAYLOAD,
    TEST_PUBKEY,
};

#[path = "common/mod.rs"]
mod common;
use common::{expect_missing_feature, handshake, shell_v2_encode, SH_EXIT, SH_STDOUT};

// ---------------------------------------------------------------------------
// Tests: connection handshake
// ---------------------------------------------------------------------------

rt_test! {
async fn connect_no_auth() {
    let (conn, device) = session(FakeDevice::new(), b"host::features=test", |_| async {}).await;

    assert_eq!(conn.device_banner(), Some(DEFAULT_BANNER));
    assert_eq!(conn.max_payload(), DEFAULT_MAX_PAYLOAD);

    rt::join(device).await;
}
}

rt_test! {
async fn connect_auth_signature() {
    let dev = FakeDevice::new().auth(AuthPolicy::AcceptSignature {
        token: b"random-token-data".to_vec(),
    });
    let (conn, device) = session(dev, b"host::", |_| async {}).await;

    assert_eq!(conn.device_banner(), Some(DEFAULT_BANNER));
    rt::join(device).await;
}
}

rt_test! {
async fn connect_auth_pubkey() {
    let dev = FakeDevice::new().auth(AuthPolicy::RequirePublicKey {
        first_token: b"token-1".to_vec(),
        second_token: b"token-2".to_vec(),
        expected_pubkey: TEST_PUBKEY.to_vec(),
    });
    let (conn, device) = session(dev, b"host::", |_| async {}).await;

    assert_eq!(conn.device_banner(), Some(DEFAULT_BANNER));
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Tests: channel operations (using Channel API)
// ---------------------------------------------------------------------------

rt_test! {
async fn open_and_close() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"shell:ls\0").await;
        ch.expect_close().await;
    })
    .await;

    let ch = conn.open(b"shell:ls\0").await.unwrap();
    ch.close().await.unwrap();

    rt::join(device).await;
}
}

rt_test! {
async fn channel_write_read_echo() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"echo:\0").await;

        ch.expect_write_ack().await;
        ch.send_write(b"hello device").await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut ch = conn.open(b"echo:\0").await.unwrap();

    ch.write(b"hello device").await.unwrap();

    let mut buf = [0u8; 64];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello device");

    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn channel_closed_by_device() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        ch.send_close().await;
    })
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();

    let mut buf = [0u8; 32];
    let err = ch.read(&mut buf).await.unwrap_err();
    assert!(matches!(err, libadb::Error::ChannelClosed));

    rt::join(device).await;
}
}

rt_test! {
async fn multiple_channels_interleaved() {
    // Multi-channel interleave: uses the low-level recv()/send() escape
    // hatch since the test doesn't fit the single-active-channel model.
    let (mut conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut channels: Vec<(u32, u32)> = Vec::new();
        let mut next_did: u32 = 100;

        loop {
            let (hdr, payload) = s.recv().await;
            match hdr.command {
                CMD_OPEN => {
                    let did = next_did;
                    next_did += 100;
                    let cid = hdr.arg0;
                    channels.push((did, cid));
                    s.send(CMD_OKAY, did, cid, &[]).await;
                }
                CMD_WRTE => {
                    let (did, cid) = channels
                        .iter()
                        .copied()
                        .find(|(did, _)| *did == hdr.arg1)
                        .unwrap();
                    s.send(CMD_OKAY, did, cid, &[]).await;
                    s.send(CMD_WRTE, did, cid, &payload).await;
                }
                CMD_OKAY => {}
                CMD_CLSE => {
                    channels.retain(|(did, _)| *did != hdr.arg1);
                    if channels.is_empty() {
                        break;
                    }
                }
                _ => panic!("unexpected command: 0x{:08X}", hdr.command),
            }
        }
    })
    .await;

    let ch1 = conn.open_channel(b"svc1:\0").await.unwrap();
    let ch2 = conn.open_channel(b"svc2:\0").await.unwrap();

    conn.write_channel(ch1, b"alpha").await.unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read_channel(ch1, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"alpha");

    conn.write_channel(ch2, b"beta").await.unwrap();
    let n = conn.read_channel(ch2, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"beta");

    conn.write_channel(ch1, b"one").await.unwrap();
    conn.write_channel(ch2, b"two").await.unwrap();

    let n = conn.read_channel(ch1, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"one");

    let n = conn.read_channel(ch2, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"two");

    conn.close_channel(ch1).await.unwrap();
    conn.close_channel(ch2).await.unwrap();

    rt::join(device).await;
}
}

rt_test! {
async fn read_partial_buffer() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"data:\0").await;

        ch.send_write(b"abcdefghijklmnop").await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut ch = conn.open(b"data:\0").await.unwrap();

    let mut small = [0u8; 4];
    let n = ch.read(&mut small).await.unwrap();
    assert_eq!(n, 4);
    assert_eq!(&small, b"abcd");

    let mut rest = [0u8; 32];
    let n = ch.read(&mut rest).await.unwrap();
    assert_eq!(n, 12);
    assert_eq!(&rest[..12], b"efghijklmnop");

    ch.close().await.unwrap();
    rt::join(device).await;
}
}
// ---------------------------------------------------------------------------
// Tests: exec: service (raw, binary-clean)
// ---------------------------------------------------------------------------

rt_test! {
async fn exec_run_collects_output_until_channel_close() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"exec:cat /data/file\0").await;
        ch.send_write(b"hello ").await;
        ch.expect_ack().await;
        ch.send_write(b"world").await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;

    let mut buf = [0u8; 128];
    let n = exec::run(&mut conn, "cat /data/file", &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello world");

    rt::join(device).await;
}
}

rt_test! {
async fn exec_run_with_empty_command_opens_default_shell() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"exec:\0").await;
        ch.send_close().await;
    })
    .await;

    let mut buf = [0u8; 64];
    let n = exec::run(&mut conn, "", &mut buf).await.unwrap();
    assert_eq!(n, 0);

    rt::join(device).await;
}
}

rt_test! {
async fn exec_run_returns_buffer_full_when_output_exceeds_capacity() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"exec:yes\0").await;
        ch.send_write(&[b'y'; 16]).await;
        ch.expect_ack().await;
        ch.send_write(&[b'y'; 16]).await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;

    let mut buf = [0u8; 32];
    let err = exec::run(&mut conn, "yes", &mut buf).await.unwrap_err();
    assert!(matches!(err, Error::ReceiveBufferFull));

    rt::join(device).await;
}
}

rt_test! {
async fn exec_open_streams_output_and_forwards_stdin() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"exec:sh\0").await;

        ch.send_write(b"ready\n").await;
        ch.expect_ack().await;

        let stdin = ch.expect_write_ack().await;
        assert_eq!(&stdin, b"echo hi\n");

        ch.send_write(b"hi\n").await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut dest_buf = [0u8; 16];
    let mut ex = exec::open(&mut conn, "sh", &mut dest_buf).await.unwrap();

    let mut buf = [0u8; 32];
    let n = ex.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ready\n");

    ex.write_stdin(b"echo hi\n").await.unwrap();

    let n = ex.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hi\n");

    ex.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn exec_open_with_tight_dest_buffer_fails_cleanly() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        if rt::timeout_ms(100, s.recv()).await.is_some() {
            panic!("client sent OPEN despite dest buffer overflow");
        }
    })
    .await;

    let mut dest_buf = [0u8; 6];
    let Err(err) = exec::open(&mut conn, "ls", &mut dest_buf).await else {
        panic!("expected Err(ReceiveBufferFull)");
    };
    assert!(matches!(err, Error::ReceiveBufferFull));

    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Tests: cmd service (abb/abb_exec priority, shell_v2,raw:cmd fallback)
// ---------------------------------------------------------------------------

rt_test! {
async fn cmd_exec_uses_abb_exec_when_advertised() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2,abb_exec".to_vec());
    let (mut conn, device) = session(dev, b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"abb_exec:package\0list\0packages\0").await;
        ch.send_write(b"package:com.example\n").await;
        ch.expect_ack().await;
        ch.send_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let output = cmd::exec(&mut conn, &["package", "list", "packages"], &mut rx)
        .await
        .unwrap();
    assert_eq!(output, b"package:com.example\n");

    rt::join(device).await;
}
}

rt_test! {
async fn cmd_exec_falls_back_to_shell_v2_when_abb_exec_missing() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=", |mut s| async move {
        let mut ch = s
            .accept_open(b"shell,v2,raw:cmd package list packages\0")
            .await;

        let mut frames = Vec::new();
        frames.extend_from_slice(&shell_v2_encode(SH_STDOUT, b"package:a\n"));
        frames.extend_from_slice(&shell_v2_encode(SH_EXIT, &[0]));
        ch.send_write(&frames).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let output = cmd::exec(&mut conn, &["package", "list", "packages"], &mut rx)
        .await
        .unwrap();
    assert_eq!(output, b"package:a\n");

    rt::join(device).await;
}
}

rt_test! {
async fn cmd_open_uses_abb_when_advertised() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2,abb".to_vec());
    let (mut conn, device) = session(dev, b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"abb:activity\0monitor\0").await;
        ch.send_write(&shell_v2_encode(SH_STDOUT, b"tick\n")).await;
        ch.expect_ack().await;
        ch.send_write(&shell_v2_encode(SH_EXIT, &[0])).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let shell = cmd::open(&mut conn, &["activity", "monitor"], &mut rx)
        .await
        .unwrap();

    let out = shell.collect().await.unwrap();
    assert_eq!(out.stdout, b"tick\n");
    assert_eq!(out.exit_code, 0);

    rt::join(device).await;
}
}

rt_test! {
async fn cmd_open_falls_back_to_shell_v2_when_abb_missing() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"shell,v2,raw:cmd connectivity\0").await;
        ch.send_write(&shell_v2_encode(SH_STDOUT, b"ok\n")).await;
        ch.expect_ack().await;
        ch.send_write(&shell_v2_encode(SH_EXIT, &[0])).await;
        ch.expect_ack().await;
        ch.expect_close().await;
    })
    .await;

    let mut rx = [0u8; 1024];
    let shell = cmd::open(&mut conn, &["connectivity"], &mut rx).await.unwrap();

    let out = shell.collect().await.unwrap();
    assert_eq!(out.stdout, b"ok\n");

    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Tests: feature negotiation
// ---------------------------------------------------------------------------

rt_test! {
async fn connect_encodes_host_features_into_cnxn_banner() {
    let (handle, addr) = FakeDevice::new().bind().await;
    let device = rt::spawn(async move { handle.accept().await.host_banner().to_vec() });

    let stream = rt::connect(addr).await;
    let _conn = Connection::<_>::connect(
        wrap(stream),
        TestAuth,
        &[Feature::ShellV2, Feature::Cmd, Feature::DelayedAck],
    )
    .await
    .unwrap();

    assert_eq!(rt::join(device).await, b"host::features=shell_v2,cmd,delayed_ack");
}
}

rt_test! {
async fn connect_with_no_host_features_emits_empty_features_value() {
    let (handle, addr) = FakeDevice::new().bind().await;
    let device = rt::spawn(async move { handle.accept().await.host_banner().to_vec() });

    let stream = rt::connect(addr).await;
    let _conn = Connection::<_>::connect(wrap(stream), TestAuth, &[]).await.unwrap();

    assert_eq!(rt::join(device).await, b"host::features=");
}
}

rt_test! {
async fn require_feature_accepts_what_device_advertises() {
    let (conn, device) = handshake(&["shell_v2", "cmd"], &[Feature::ShellV2]).await;

    assert!(conn.require_feature(Feature::ShellV2).is_ok());
    assert!(conn.require_feature(Feature::Cmd).is_ok());

    rt::join(device).await;
}
}

rt_test! {
async fn require_feature_rejects_what_device_omits() {
    let (conn, device) = handshake(&["cmd"], &[]).await;

    expect_missing_feature(conn.require_feature(Feature::ShellV2), Feature::ShellV2);

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v2_open_gated_on_shell_v2() {
    let (mut conn, device) = handshake(&["cmd"], &[]).await;
    let mut rx = [0u8; 1024];

    expect_missing_feature(
        shell_v2::open(&mut conn, "ls", &mut rx).await,
        Feature::ShellV2,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v2_open_interactive_gated_on_shell_v2() {
    let (mut conn, device) = handshake(&["cmd"], &[]).await;
    let mut rx = [0u8; 1024];

    expect_missing_feature(
        shell_v2::open_interactive(&mut conn, "", "", None, &mut rx).await,
        Feature::ShellV2,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn abb_open_gated_on_abb() {
    let (mut conn, device) = handshake(&["shell_v2"], &[]).await;
    let mut rx = [0u8; 1024];

    expect_missing_feature(
        abb::open(&mut conn, &["activity", "monitor"], &mut rx).await,
        Feature::Abb,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn abb_open_exec_gated_on_abb_exec() {
    let (mut conn, device) = handshake(&["abb"], &[]).await;

    expect_missing_feature(
        abb::open_exec(&mut conn, &["package", "list", "packages"]).await,
        Feature::AbbExec,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn track_app_open_gated_on_track_app() {
    let (mut conn, device) = handshake(&["shell_v2"], &[]).await;
    let mut rx = [0u8; 1024];

    expect_missing_feature(
        track_app::open(&mut conn, &mut rx).await,
        Feature::TrackApp,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn logcat_open_gated_on_shell_v2() {
    let (mut conn, device) = handshake(&["cmd"], &[]).await;
    let mut rx = [0u8; 1024];

    expect_missing_feature(
        logcat::open(&mut conn, &[], &mut rx).await,
        Feature::ShellV2,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v2_open_sends_no_open_packet_when_feature_missing() {
    let dev = FakeDevice::new().banner(b"device::features=cmd".to_vec());
    let (mut conn, device) = session(dev, b"host::features=", |mut s| async move {
        if rt::timeout_ms(150, s.recv()).await.is_some() {
            panic!("client sent packet despite missing feature gate");
        }
    })
    .await;
    let mut rx = [0u8; 1024];

    expect_missing_feature(
        shell_v2::open(&mut conn, "ls", &mut rx).await,
        Feature::ShellV2,
    );

    rt::join(device).await;
}
}

rt_test! {
async fn shell_v2_open_succeeds_when_feature_advertised() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) =
        session(dev, b"host::features=shell_v2", |mut s| async move {
            let mut ch = s.accept_open(b"shell,v2,raw:ls\0").await;
            ch.send_close().await;
        })
        .await;
    let mut rx = [0u8; 1024];
    let _shell = shell_v2::open(&mut conn, "ls", &mut rx).await.unwrap();

    rt::join(device).await;
}
}

rt_test! {
async fn require_feature_works_after_connect_with_raw_banner() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2,cmd".to_vec());
    let (conn, device) =
        session(dev, b"host::features=shell_v2", |_| async {}).await;

    assert!(conn.require_feature(Feature::ShellV2).is_ok());
    expect_missing_feature(conn.require_feature(Feature::TrackApp), Feature::TrackApp);

    rt::join(device).await;
}
}
