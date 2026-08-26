#![allow(dead_code)]

use libadb::protocol::features::Feature;
use libadb::{Connection, Error};

/// shell_v2 wire frame IDs.
pub const SH_STDOUT: u8 = 1;
pub const SH_STDERR: u8 = 2;
pub const SH_EXIT: u8 = 3;
pub const SH_CLOSE_STDIN: u8 = 4;

/// Encode a shell_v2 packet: `[id: u8, length: u32 LE, payload...]`.
pub fn shell_v2_encode(id: u8, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() as u32).to_le_bytes();
    let mut pkt = Vec::with_capacity(5 + payload.len());
    pkt.push(id);
    pkt.extend_from_slice(&len);
    pkt.extend_from_slice(payload);
    pkt
}

/// Parse a 5-byte shell_v2 message → `(id, payload_length)`.
pub fn shell_v2_parse(buf: &[u8; 5]) -> (u8, u32) {
    (buf[0], u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]))
}

use crate::fake_device::{wrap, FakeDevice, FakeSession, TestAuth};
use crate::rt::{self, JoinHandle};

pub async fn handshake(
    device_features: &[&str],
    host_features: &[Feature],
) -> (Connection<rt::AdbTransport>, JoinHandle<FakeSession>) {
    let banner = format!("device::features={}", device_features.join(","));
    let (handle, addr) = FakeDevice::new().banner(banner.into_bytes()).bind().await;
    let device = rt::spawn(async move { handle.accept().await });
    let stream = rt::connect(addr).await;
    let conn = Connection::<_>::connect(wrap(stream), TestAuth, host_features)
        .await
        .unwrap();
    (conn, device)
}

pub fn expect_missing_feature<T, E: core::fmt::Debug>(
    result: Result<T, Error<E>>,
    expected: Feature,
) {
    let Err(err) = result else {
        panic!("expected Err(MissingFeature({expected:?})), got Ok");
    };
    assert!(
        matches!(err, Error::MissingFeature(f) if f == expected),
        "expected MissingFeature({expected:?}), got {err:?}",
    );
}

#[macro_export]
macro_rules! rt_test {
    ($(#[$attr:meta])* async fn $name:ident() $body:block) => {
        $(#[$attr])*
        #[test]
        fn $name() {
            $crate::rt::block_on(async move $body);
        }
    };
}
