#![cfg(any(feature = "tokio", feature = "smol"))]

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/mod.rs"]
mod common;

// ---------------------------------------------------------------------------
// Tests: delayed ACK (credit-based flow control)
// ---------------------------------------------------------------------------

const DA_BANNER: &[u8] = b"device::features=shell_v2,delayed_ack";
const DA_MAX_PAYLOAD: u32 = 1024;

fn da_device(initial_asb: u32) -> FakeDevice {
    FakeDevice::new()
        .banner(DA_BANNER)
        .max_payload(DA_MAX_PAYLOAD)
        .delayed_ack(initial_asb)
}

rt_test! {
async fn delayed_ack_negotiated() {
    let (conn, device) = session(da_device(0), b"host::features=delayed_ack", |_| async {}).await;

    assert!(conn.delayed_ack());
    rt::join(device).await;
}
}

rt_test! {
async fn delayed_ack_not_negotiated_when_device_lacks_feature() {
    // Device banner WITHOUT delayed_ack.
    let (conn, device) = session(
        FakeDevice::new(),
        b"host::features=delayed_ack",
        |_| async {},
    )
    .await;

    assert!(!conn.delayed_ack());
    rt::join(device).await;
}
}

rt_test! {
async fn delayed_ack_not_negotiated_when_host_lacks_feature() {
    let (conn, device) =
        session(da_device(0), b"host::features=shell_v2", |_| async {}).await;

    assert!(!conn.delayed_ack());
    rt::join(device).await;
}
}

rt_test! {
async fn delayed_ack_burst_write() {
    // With enough initial ASB, all WRTEs should be sent back-to-back
    // without intermediate OKAYs.
    let (mut conn, device) = session(
        da_device(4096),
        b"host::features=delayed_ack",
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;

            for i in 0..3 {
                let p = ch.expect_write().await;
                assert_eq!(p.len(), DA_MAX_PAYLOAD as usize, "WRTE #{i} size");
            }
            for _ in 0..3 {
                ch.ack(DA_MAX_PAYLOAD).await;
            }
            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    ch.write(&vec![0xAA; 3 * DA_MAX_PAYLOAD as usize])
        .await
        .unwrap();
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn delayed_ack_budget_exhaustion() {
    // Initial ASB = 2 * max_payload — client bursts two full chunks,
    // then parks. Granting one full payload unblocks the third.
    let (mut conn, device) = session(
        da_device(2 * DA_MAX_PAYLOAD),
        b"host::features=delayed_ack",
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;

            let p1 = ch.expect_write().await;
            assert_eq!(p1.len(), DA_MAX_PAYLOAD as usize);
            let p2 = ch.expect_write().await;
            assert_eq!(p2.len(), DA_MAX_PAYLOAD as usize);

            ch.ack(DA_MAX_PAYLOAD).await;

            let p3 = ch.expect_write().await;
            assert_eq!(p3.len(), DA_MAX_PAYLOAD as usize);
            ch.ack(DA_MAX_PAYLOAD).await;

            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    ch.write(&vec![0xBB; 3 * DA_MAX_PAYLOAD as usize])
        .await
        .unwrap();
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn delayed_ack_okay_carries_payload() {
    // WRTE → OKAY round-trip: the client's OKAY must carry a 4-byte
    // payload with the acknowledged byte count.
    let (mut conn, device) = session(
        da_device(4096),
        b"host::features=delayed_ack",
        |mut s| async move {
            let mut ch = s.accept_open(b"svc:\0").await;

            ch.send_write(b"hello").await;
            let acked = ch.expect_ack().await;
            assert_eq!(acked, 5);

            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"svc:\0").await.unwrap();
    let mut buf = [0u8; 64];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    ch.close().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn delayed_ack_write_read_echo() {
    let (mut conn, device) = session(
        da_device(8192),
        b"host::features=delayed_ack",
        |mut s| async move {
            let mut ch = s.accept_open(b"echo:\0").await;

            let data = ch.expect_write().await;
            assert_eq!(&data, b"ping");
            ch.ack(data.len() as u32).await;

            ch.send_write(b"pong").await;
            let acked = ch.expect_ack().await;
            assert_eq!(acked, 4);

            ch.expect_close().await;
        },
    )
    .await;

    let mut ch = conn.open(b"echo:\0").await.unwrap();
    ch.write(b"ping").await.unwrap();

    let mut buf = [0u8; 64];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong");

    ch.close().await.unwrap();
    rt::join(device).await;
}
}
