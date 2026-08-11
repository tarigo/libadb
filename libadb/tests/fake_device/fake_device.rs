//! Declarative test fixture for driving the device side of an ADB
//! session in integration tests.
//!
//! Configure the CNXN banner, max payload, auth policy, and delayed-ACK
//! mode up front, bind a listener, then call [`FakeDeviceHandle::accept`]
//! in a spawned task. The returned [`FakeSession`] exposes
//! [`accept_open`][FakeSession::accept_open] which performs the OPEN→OKAY
//! exchange and returns a [`FakeChannel`] with typed, per-channel methods
//! ([`expect_write`][FakeChannel::expect_write],
//! [`send_write`][FakeChannel::send_write], [`ack`][FakeChannel::ack],
//! [`expect_close`][FakeChannel::expect_close], etc.).
//!
//! Delayed-ACK bookkeeping (4-byte OKAY payloads, initial ASB on
//! OPEN→OKAY) is hidden once [`FakeDevice::delayed_ack`] is configured.
//!
//! For multi-channel interleaving tests that don't fit the single-active
//! channel model, fall back to the low-level
//! [`recv`][FakeSession::recv] / [`send`][FakeSession::send] methods.

#![allow(dead_code)]

use std::net::SocketAddr;

use libadb::protocol::command::{self, CMD_AUTH, CMD_CLSE, CMD_CNXN, CMD_OKAY, CMD_OPEN, CMD_WRTE};
use libadb::protocol::constant::{AUTH_RSAPUBLICKEY, AUTH_SIGNATURE, AUTH_TOKEN};
use libadb::protocol::features::{has_feature, DELAYED_ACK, INITIAL_DELAYED_ACK_BYTES};

use crate::rt::{self, TcpListener, TcpStream};

const HEADER_SIZE: usize = 24;

/// 24-byte ADB wire header, used by this fixture only.
#[derive(Debug, Clone, Copy)]
pub struct MsgHeader {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
}

fn encode_header(cmd: u32, arg0: u32, arg1: u32, payload: &[u8], dst: &mut [u8; HEADER_SIZE]) {
    let data_length = payload.len() as u32;
    let data_check = payload
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
    let magic = command::magic(cmd);
    dst[0..4].copy_from_slice(&cmd.to_le_bytes());
    dst[4..8].copy_from_slice(&arg0.to_le_bytes());
    dst[8..12].copy_from_slice(&arg1.to_le_bytes());
    dst[12..16].copy_from_slice(&data_length.to_le_bytes());
    dst[16..20].copy_from_slice(&data_check.to_le_bytes());
    dst[20..24].copy_from_slice(&magic.to_le_bytes());
}

fn decode_header(src: &[u8; HEADER_SIZE]) -> MsgHeader {
    let command = u32::from_le_bytes(src[0..4].try_into().unwrap());
    let magic = u32::from_le_bytes(src[20..24].try_into().unwrap());
    assert_eq!(
        magic,
        command::magic(command),
        "magic mismatch in wire header",
    );
    MsgHeader {
        command,
        arg0: u32::from_le_bytes(src[4..8].try_into().unwrap()),
        arg1: u32::from_le_bytes(src[8..12].try_into().unwrap()),
        data_length: u32::from_le_bytes(src[12..16].try_into().unwrap()),
    }
}

pub const DEFAULT_BANNER: &[u8] = b"device::ro.product.model=FakeADB";
pub const DEFAULT_MAX_PAYLOAD: u32 = 4096;

pub const TEST_SIGNATURE: &[u8] = b"test-signature";
pub const TEST_PUBKEY: &[u8] = b"test-pubkey user@host\0";

/// Auth handshake the fake device performs after the initial CNXN.
#[derive(Clone)]
pub enum AuthPolicy {
    /// Accept immediately — no AUTH exchange.
    None,
    /// Send `AUTH(TOKEN, token)`, expect `AUTH(SIGNATURE, _)`, then accept.
    AcceptSignature { token: Vec<u8> },
    /// Send first `AUTH(TOKEN)`, expect SIGNATURE, reject; send second
    /// `AUTH(TOKEN)`, expect `AUTH(RSAPUBLICKEY)` whose payload equals
    /// `expected_pubkey`, then accept.
    RequirePublicKey {
        first_token: Vec<u8>,
        second_token: Vec<u8>,
        expected_pubkey: Vec<u8>,
    },
}

/// Declarative configuration for a fake ADB device.
pub struct FakeDevice {
    banner: Vec<u8>,
    max_payload: u32,
    initial_asb: Option<u32>,
    auth: AuthPolicy,
}

impl Default for FakeDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDevice {
    pub fn new() -> Self {
        Self {
            banner: DEFAULT_BANNER.to_vec(),
            max_payload: DEFAULT_MAX_PAYLOAD,
            initial_asb: None,
            auth: AuthPolicy::None,
        }
    }

    pub fn banner(mut self, banner: impl Into<Vec<u8>>) -> Self {
        self.banner = banner.into();
        self
    }

    pub fn max_payload(mut self, max_payload: u32) -> Self {
        self.max_payload = max_payload;
        self
    }

    /// Configure delayed-ACK mode on the device side. The banner must
    /// advertise `features=...delayed_ack...` — this is asserted in
    /// [`bind`][Self::bind] so misconfiguration fails fast.
    ///
    /// Whether the session actually operates in delayed-ACK mode depends
    /// on negotiation: if the host's CNXN banner also advertises the
    /// feature, the OPEN→OKAY reply carries `initial_asb` as a 4-byte
    /// payload and subsequent OKAYs ([`FakeChannel::ack`]) carry 4-byte
    /// credit payloads. If the host does not advertise it, the session
    /// silently falls back to legacy semantics (matching the client).
    /// Use [`FakeSession::is_delayed_ack`] to observe the negotiated state.
    pub fn delayed_ack(mut self, initial_asb: u32) -> Self {
        self.initial_asb = Some(initial_asb);
        self
    }

    pub fn auth(mut self, policy: AuthPolicy) -> Self {
        self.auth = policy;
        self
    }

    /// Bind a TCP listener on a random localhost port. Connect the client to
    /// the returned [`SocketAddr`].
    pub async fn bind(self) -> (FakeDeviceHandle, SocketAddr) {
        if self.initial_asb.is_some() {
            assert!(
                has_feature(&self.banner, DELAYED_ACK),
                "FakeDevice: .delayed_ack(...) was configured but the banner \
                 does not advertise `delayed_ack`. Update .banner(...) to include \
                 `features=...,delayed_ack,...` before calling .bind()."
            );
        }
        let (listener, addr) = rt::bind_loopback().await;
        (
            FakeDeviceHandle {
                listener,
                config: self,
            },
            addr,
        )
    }
}

pub struct FakeDeviceHandle {
    listener: TcpListener,
    config: FakeDevice,
}

impl FakeDeviceHandle {
    /// Accept the incoming client connection and perform the configured
    /// CNXN/AUTH handshake. Panics on any protocol mismatch.
    pub async fn accept(self) -> FakeSession {
        let stream = rt::accept_one(&self.listener).await;
        let mut session = FakeSession {
            stream,
            delayed_ack: false,
            initial_asb: self.config.initial_asb.unwrap_or(0),
            next_device_id: 1,
            host_banner: Vec::new(),
        };
        session.handshake(&self.config).await;
        session
    }
}

pub struct FakeSession {
    stream: TcpStream,
    delayed_ack: bool,
    initial_asb: u32,
    next_device_id: u32,
    host_banner: Vec<u8>,
}

impl FakeSession {
    async fn handshake(&mut self, config: &FakeDevice) {
        let (hdr, host_banner) = self.recv().await;
        assert_eq!(
            hdr.command, CMD_CNXN,
            "expected CNXN, got 0x{:08X}",
            hdr.command
        );

        // delayed_ack is negotiated: both sides must advertise it.
        // `bind()` already guaranteed `initial_asb.is_some() ⇒ device
        // banner advertises`; here we check the host side. Uses the same
        // `has_feature` helper the library itself uses for negotiation,
        // so the fixture can't drift from the client under test.
        self.delayed_ack = config.initial_asb.is_some() && has_feature(&host_banner, DELAYED_ACK);
        self.host_banner = host_banner;

        match &config.auth {
            AuthPolicy::None => {}
            AuthPolicy::AcceptSignature { token } => {
                self.send(CMD_AUTH, AUTH_TOKEN, 0, token).await;
                let (h, _) = self.expect(CMD_AUTH).await;
                assert_eq!(h.arg0, AUTH_SIGNATURE, "expected SIGNATURE");
            }
            AuthPolicy::RequirePublicKey {
                first_token,
                second_token,
                expected_pubkey,
            } => {
                self.send(CMD_AUTH, AUTH_TOKEN, 0, first_token).await;
                let (h, _) = self.expect(CMD_AUTH).await;
                assert_eq!(h.arg0, AUTH_SIGNATURE);

                self.send(CMD_AUTH, AUTH_TOKEN, 0, second_token).await;
                let (h, pk) = self.expect(CMD_AUTH).await;
                assert_eq!(h.arg0, AUTH_RSAPUBLICKEY);
                assert_eq!(&pk, expected_pubkey, "RSAPUBLICKEY payload mismatch");
            }
        }

        self.send(
            CMD_CNXN,
            libadb::protocol::constant::ADB_VERSION,
            config.max_payload,
            &config.banner,
        )
        .await;
    }

    pub fn is_delayed_ack(&self) -> bool {
        self.delayed_ack
    }

    /// Raw `host::...` banner the client sent in its CNXN message.
    pub fn host_banner(&self) -> &[u8] {
        &self.host_banner
    }

    /// Low-level: send a message with command + args + payload.
    pub async fn send(&mut self, cmd: u32, arg0: u32, arg1: u32, payload: &[u8]) {
        let mut buf = [0u8; HEADER_SIZE];
        encode_header(cmd, arg0, arg1, payload, &mut buf);
        rt::write_all(&mut self.stream, &buf).await;
        if !payload.is_empty() {
            rt::write_all(&mut self.stream, payload).await;
        }
    }

    /// Low-level: receive the next message and its payload.
    pub async fn recv(&mut self) -> (MsgHeader, Vec<u8>) {
        let mut buf = [0u8; HEADER_SIZE];
        rt::read_exact(&mut self.stream, &mut buf).await;
        let hdr = decode_header(&buf);
        let mut payload = vec![0u8; hdr.data_length as usize];
        if !payload.is_empty() {
            rt::read_exact(&mut self.stream, &mut payload).await;
        }
        (hdr, payload)
    }

    /// Low-level: receive and assert the command code.
    pub async fn expect(&mut self, cmd: u32) -> (MsgHeader, Vec<u8>) {
        let (hdr, payload) = self.recv().await;
        assert_eq!(
            hdr.command, cmd,
            "expected command 0x{:08X}, got 0x{:08X}",
            cmd, hdr.command,
        );
        (hdr, payload)
    }

    /// Accept a client OPEN whose destination equals `expected_dest`,
    /// reply with OKAY, and return a [`FakeChannel`] handle.
    pub async fn accept_open(&mut self, expected_dest: &[u8]) -> FakeChannel<'_> {
        let (ch, dest) = self.accept_open_any().await;
        assert_eq!(
            dest, expected_dest,
            "OPEN destination mismatch: got {:?}",
            dest
        );
        ch
    }

    /// Accept the next client OPEN with any destination. Returns both the
    /// channel and the raw destination string for inspection.
    pub async fn accept_open_any(&mut self) -> (FakeChannel<'_>, Vec<u8>) {
        let (hdr, dest) = self.expect(CMD_OPEN).await;
        let client_id = hdr.arg0;
        if self.delayed_ack {
            assert_eq!(
                hdr.arg1, INITIAL_DELAYED_ACK_BYTES,
                "OPEN arg1 must carry INITIAL_DELAYED_ACK_BYTES"
            );
        }
        let device_id = self.next_device_id;
        self.next_device_id += 1;

        if self.delayed_ack {
            let asb = self.initial_asb.to_le_bytes();
            self.send(CMD_OKAY, device_id, client_id, &asb).await;
        } else {
            self.send(CMD_OKAY, device_id, client_id, &[]).await;
        }

        let ch = FakeChannel {
            session: self,
            device_id,
            client_id,
        };
        (ch, dest)
    }
}

/// Single open channel on the fake device.
///
/// Holds a mutable borrow on [`FakeSession`], so only one `FakeChannel`
/// can be active at a time. For interleaved multi-channel tests, use
/// [`FakeSession::recv`] / [`FakeSession::send`] directly.
pub struct FakeChannel<'a> {
    session: &'a mut FakeSession,
    device_id: u32,
    client_id: u32,
}

impl<'a> FakeChannel<'a> {
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    pub fn client_id(&self) -> u32 {
        self.client_id
    }

    /// Expect a CMD_WRTE from the client; return its payload. Does NOT
    /// send an OKAY — in delayed-ACK tests the caller decides when to
    /// ack (see [`ack`][Self::ack]).
    pub async fn expect_write(&mut self) -> Vec<u8> {
        let (hdr, payload) = self.session.expect(CMD_WRTE).await;
        assert_eq!(hdr.arg0, self.client_id, "WRTE arg0 (client_id) mismatch");
        assert_eq!(hdr.arg1, self.device_id, "WRTE arg1 (device_id) mismatch");
        payload
    }

    /// Expect a CMD_WRTE and assert its payload equals `expected`.
    pub async fn expect_write_eq(&mut self, expected: &[u8]) {
        let payload = self.expect_write().await;
        assert_eq!(payload, expected, "WRTE payload mismatch");
    }

    /// Expect a CMD_WRTE and immediately send its OKAY (with
    /// `payload.len()` as the acked byte count in delayed-ACK mode).
    pub async fn expect_write_ack(&mut self) -> Vec<u8> {
        let payload = self.expect_write().await;
        let n = payload.len() as u32;
        self.ack(n).await;
        payload
    }

    /// Send OKAY to the client. In legacy mode `acked` is ignored
    /// (empty payload); in delayed-ACK mode it becomes the 4-byte payload.
    pub async fn ack(&mut self, acked: u32) {
        if self.session.delayed_ack {
            let bytes = acked.to_le_bytes();
            self.session
                .send(CMD_OKAY, self.device_id, self.client_id, &bytes)
                .await;
        } else {
            self.session
                .send(CMD_OKAY, self.device_id, self.client_id, &[])
                .await;
        }
    }

    /// Send CMD_WRTE with `data` to the client.
    pub async fn send_write(&mut self, data: &[u8]) {
        self.session
            .send(CMD_WRTE, self.device_id, self.client_id, data)
            .await;
    }

    /// Expect CMD_OKAY from the client. In delayed-ACK mode, returns
    /// the acked byte count; in legacy mode returns 0.
    pub async fn expect_ack(&mut self) -> u32 {
        let (hdr, payload) = self.session.expect(CMD_OKAY).await;
        assert_eq!(hdr.arg0, self.client_id);
        assert_eq!(hdr.arg1, self.device_id);
        if self.session.delayed_ack {
            assert_eq!(
                payload.len(),
                4,
                "delayed_ack OKAY must have 4-byte payload"
            );
            u32::from_le_bytes(payload[..4].try_into().unwrap())
        } else {
            0
        }
    }

    /// Expect CMD_CLSE from the client.
    pub async fn expect_close(&mut self) {
        let (hdr, _) = self.session.expect(CMD_CLSE).await;
        assert_eq!(hdr.arg0, self.client_id);
        assert_eq!(hdr.arg1, self.device_id);
    }

    /// Send CMD_CLSE to the client.
    pub async fn send_close(&mut self) {
        self.session
            .send(CMD_CLSE, self.device_id, self.client_id, &[])
            .await;
    }

    /// Low-level escape hatch: receive the next message on the session,
    /// whichever command it carries. Useful for tests with interleaved
    /// client/device traffic (e.g. bidirectional echo + flow-control
    /// OKAYs) that don't fit the strict expect/send sequence of the
    /// typed helpers.
    pub async fn recv_any(&mut self) -> (MsgHeader, Vec<u8>) {
        self.session.recv().await
    }
}

// ---------------------------------------------------------------------------
// Client-side helpers shared across integration test binaries.
// ---------------------------------------------------------------------------

pub struct TestAuth;

impl libadb::auth::Authenticator for TestAuth {
    type Error = core::convert::Infallible;

    async fn sign(&mut self, _token: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(TEST_SIGNATURE.to_vec())
    }

    fn public_key(&self) -> &[u8] {
        TEST_PUBKEY
    }
}

pub fn wrap(stream: TcpStream) -> rt::AdbTransport {
    rt::wrap(stream)
}

/// Spawn `scenario` on the device side and return a connected client
/// `Connection` after the CNXN handshake completes with `host_banner`.
pub async fn session<F, Fut, R>(
    device: FakeDevice,
    host_banner: &[u8],
    scenario: F,
) -> (libadb::Connection<rt::AdbTransport>, rt::JoinHandle<R>)
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
    let conn =
        libadb::Connection::<_>::connect_with_raw_banner(wrap(stream), TestAuth, host_banner)
            .await
            .unwrap();
    (conn, task)
}
