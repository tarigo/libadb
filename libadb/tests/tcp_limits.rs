#![cfg(any(feature = "tokio", feature = "smol"))]

//! Resource limits: what the host advertises in CNXN, what it accepts
//! from the device, how much credit it grants, and how much it is
//! willing to buffer per channel.

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{wrap, FakeDevice, FakeSession, TestAuth};

#[path = "common/common.rs"]
mod common;

use libadb::protocol::command::CMD_WRTE;
use libadb::protocol::constant::MAX_PAYLOAD;
use libadb::protocol::features::INITIAL_DELAYED_ACK_BYTES;
use libadb::{Connection, ConnectionConfig, Error, ProtocolError};

/// Same as `fake_device::session`, but drives the handshake through
/// `connect_with_config`.
async fn session_with_config<F, Fut, R>(
    device: FakeDevice,
    host_banner: &[u8],
    config: ConnectionConfig,
    scenario: F,
) -> (Connection<rt::AdbTransport>, rt::JoinHandle<R>)
where
    F: FnOnce(FakeSession) -> Fut + Send + 'static,
    Fut: core::future::Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let (handle, addr) = device.bind().await;
    let task = rt::spawn(async move {
        let s = handle.accept().await;
        scenario(s).await
    });
    let stream = rt::connect(addr).await;
    let conn = Connection::<_>::connect_with_raw_banner_and_config(
        wrap(stream),
        TestAuth,
        host_banner,
        config,
    )
    .await
    .unwrap();
    (conn, task)
}

const HOST_BANNER: &[u8] = b"host::features=shell_v2";
const DA_HOST_BANNER: &[u8] = b"host::features=shell_v2,delayed_ack";
const DA_DEVICE_BANNER: &[u8] = b"device::features=shell_v2,delayed_ack";

// ---------------------------------------------------------------------------
// What we advertise in CNXN
// ---------------------------------------------------------------------------

rt_test! {
async fn default_config_advertises_the_library_maximum() {
    let (_conn, device) = session_with_config(
        FakeDevice::new(),
        HOST_BANNER,
        ConnectionConfig::new(),
        |s| async move { s },
    )
    .await;

    let s = rt::join(device).await;
    assert_eq!(
        s.host_max_payload(),
        MAX_PAYLOAD,
        "the default config must keep advertising 1 MiB"
    );
}
}

rt_test! {
async fn configured_max_payload_is_advertised_in_cnxn() {
    let (conn, device) = session_with_config(
        FakeDevice::new(),
        HOST_BANNER,
        ConnectionConfig::new().with_max_payload(8 * 1024),
        |s| async move { s },
    )
    .await;

    let s = rt::join(device).await;
    assert_eq!(s.host_max_payload(), 8 * 1024);
    assert_eq!(conn.config().max_payload(), 8 * 1024);
}
}

// ---------------------------------------------------------------------------
// What we accept from the device
// ---------------------------------------------------------------------------

rt_test! {
async fn inbound_packet_at_the_limit_is_accepted() {
    const LIMIT: usize = 8 * 1024;

    let (mut conn, device) = session_with_config(
        FakeDevice::new().max_payload(LIMIT as u32),
        HOST_BANNER,
        ConnectionConfig::new().with_max_payload(LIMIT as u32),
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;
            ch.send_write(&vec![0x7Eu8; LIMIT]).await;
            ch.expect_ack().await;
            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    let mut buf = vec![0u8; LIMIT];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(n, LIMIT);
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn inbound_packet_above_the_limit_is_rejected() {
    const LIMIT: u32 = 8 * 1024;

    // A misbehaving (or simply legacy-1-MiB) device ignores our
    // advertised limit and sends a bigger WRTE. We must fail loudly
    // instead of growing the receive buffer to fit it.
    let (mut conn, device) = session_with_config(
        FakeDevice::new().max_payload(LIMIT),
        HOST_BANNER,
        ConnectionConfig::new().with_max_payload(LIMIT),
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;
            ch.send_write(&vec![0x5Au8; LIMIT as usize + 1]).await;
            s
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    let mut buf = vec![0u8; 64];
    let err = ch.read(&mut buf).await.unwrap_err();
    assert!(
        matches!(err, Error::Protocol(ProtocolError::PayloadTooLarge)),
        "expected PayloadTooLarge, got {err:?}"
    );
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// What we send: clamped by the device's CNXN and by our own encoder
// ---------------------------------------------------------------------------

rt_test! {
async fn outbound_chunks_are_clamped_to_the_library_maximum() {
    // The device announces more than this library can encode. Chunking
    // must fall back to MAX_PAYLOAD instead of producing packets the
    // encoder rejects.
    let (mut conn, device) = session_with_config(
        FakeDevice::new().max_payload(2 * MAX_PAYLOAD),
        HOST_BANNER,
        ConnectionConfig::new(),
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;

            let first = ch.expect_write().await;
            assert_eq!(first.len(), MAX_PAYLOAD as usize);
            ch.ack(first.len() as u32).await;

            let second = ch.expect_write().await;
            assert_eq!(second.len(), 1);
            ch.ack(1).await;

            ch.expect_close().await;
        },
    )
    .await;

    assert_eq!(
        conn.max_payload(),
        MAX_PAYLOAD,
        "an over-large device max_payload must be clamped"
    );

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    ch.write(&vec![0xC3u8; MAX_PAYLOAD as usize + 1])
        .await
        .unwrap();
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Delayed-ACK credit
// ---------------------------------------------------------------------------

rt_test! {
async fn default_open_grants_the_aosp_credit() {
    let (mut conn, device) = session_with_config(
        FakeDevice::new()
            .banner(DA_DEVICE_BANNER)
            .delayed_ack(4096),
        DA_HOST_BANNER,
        ConnectionConfig::new(),
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;
            ch.expect_close().await;
            s
        },
    )
    .await;

    let ch = conn.open(b"svc:\0").await.unwrap();
    ch.close().await.unwrap();

    let s = rt::join(device).await;
    assert_eq!(s.last_open_asb(), Some(INITIAL_DELAYED_ACK_BYTES));
}
}

rt_test! {
async fn open_grants_the_configured_credit() {
    const CREDIT: u32 = 32 * 1024;

    let (mut conn, device) = session_with_config(
        FakeDevice::new()
            .banner(DA_DEVICE_BANNER)
            .delayed_ack(4096)
            .expect_open_asb(Some(CREDIT)),
        DA_HOST_BANNER,
        ConnectionConfig::new().with_initial_ack_bytes(CREDIT),
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;
            ch.expect_close().await;
            s
        },
    )
    .await;

    let ch = conn.open(b"svc:\0").await.unwrap();
    ch.close().await.unwrap();

    let s = rt::join(device).await;
    assert_eq!(s.last_open_asb(), Some(CREDIT));
}
}

// ---------------------------------------------------------------------------
// Per-channel buffering cap
// ---------------------------------------------------------------------------

rt_test! {
async fn background_channel_buffering_is_capped() {
    const CHUNK: usize = 4096;

    // While the caller reads channel A, the device floods channel B.
    // Those bytes pile up in B's slot; past the cap we must report an
    // error rather than buffer without bound.
    let (mut conn, device) = session_with_config(
        FakeDevice::new().max_payload(CHUNK as u32),
        HOST_BANNER,
        ConnectionConfig::new()
            .with_max_payload(CHUNK as u32)
            .with_max_rx_per_channel(2 * CHUNK),
        |mut s| async move {
            let (ch_a, _) = s.accept_open_any().await;
            let _ = ch_a.device_id();
            let (ch_b, _) = s.accept_open_any().await;
            let (b_dev, b_cli) = (ch_b.device_id(), ch_b.client_id());

            for _ in 0..3 {
                s.send(CMD_WRTE, b_dev, b_cli, &vec![0xEEu8; CHUNK]).await;
            }
            // Keep the socket alive while the client reacts.
            s
        },
    )
    .await;

    let a = conn.open_channel(b"a:\0").await.unwrap();
    let _b = conn.open_channel(b"b:\0").await.unwrap();

    let mut buf = [0u8; 64];
    let err = conn.read_channel(a, &mut buf).await.unwrap_err();
    assert!(
        matches!(err, Error::ChannelRxOverflow),
        "expected ChannelRxOverflow, got {err:?}"
    );
    rt::join(device).await;
}
}

rt_test! {
async fn buffering_below_the_cap_is_fine() {
    const CHUNK: usize = 4096;

    let (mut conn, device) = session_with_config(
        FakeDevice::new().max_payload(CHUNK as u32),
        HOST_BANNER,
        ConnectionConfig::new()
            .with_max_payload(CHUNK as u32)
            .with_max_rx_per_channel(4 * CHUNK),
        |mut s| async move {
            let (ch_a, _) = s.accept_open_any().await;
            let (a_dev, a_cli) = (ch_a.device_id(), ch_a.client_id());
            let (ch_b, _) = s.accept_open_any().await;
            let (b_dev, b_cli) = (ch_b.device_id(), ch_b.client_id());

            for _ in 0..2 {
                s.send(CMD_WRTE, b_dev, b_cli, &vec![0xEEu8; CHUNK]).await;
            }
            s.send(CMD_WRTE, a_dev, a_cli, b"done").await;
            s
        },
    )
    .await;

    let a = conn.open_channel(b"a:\0").await.unwrap();
    let b = conn.open_channel(b"b:\0").await.unwrap();

    let mut buf = [0u8; 64];
    let n = conn.read_channel(a, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"done");

    // B's traffic was buffered, not dropped.
    let mut big = vec![0u8; 2 * CHUNK];
    let n = conn.read_channel(b, &mut big).await.unwrap();
    assert_eq!(n, 2 * CHUNK);
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// The split Reader/Writer pair inherits the same limits
// ---------------------------------------------------------------------------

rt_test! {
async fn split_reader_honours_the_configured_limits() {
    const LIMIT: u32 = 8 * 1024;
    const CREDIT: u32 = 16 * 1024;

    let (conn, device) = session_with_config(
        FakeDevice::new()
            .banner(DA_DEVICE_BANNER)
            .max_payload(LIMIT)
            .delayed_ack(4096)
            .expect_open_asb(Some(CREDIT)),
        DA_HOST_BANNER,
        ConnectionConfig::new()
            .with_max_payload(LIMIT)
            .with_initial_ack_bytes(CREDIT),
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;
            ch.send_write(&vec![0x11u8; LIMIT as usize + 1]).await;
            s
        },
    )
    .await;

    let (mut reader, _writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    let mut buf = vec![0u8; 64];
    let err = reader.read_channel(ch, &mut buf).await.unwrap_err();
    assert!(
        matches!(err, Error::Protocol(ProtocolError::PayloadTooLarge)),
        "expected PayloadTooLarge, got {err:?}"
    );
    rt::join(device).await;
}
}
