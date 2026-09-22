//! The TLS transport against a real `rustls` server.
//!
//! The device side here is deliberately written in a different style
//! from the client under test: blocking, on its own thread, over
//! `rustls`' own blocking stream. An oracle that reuses the code it is
//! checking proves nothing.

#![cfg(all(feature = "tls", any(feature = "tokio", feature = "smol")))]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::JoinHandle;

use embedded_io_async::{Read, Write};
use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{cert, AdbKey};
use libadb::tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use libadb::tls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use libadb::tls::rustls::{DistinguishedName, ServerConfig, ServerConnection, StreamOwned};
use libadb::tls::{rustls, TlsClientConfig, TlsIdentity};
use libadb::transport::tls::{MaybeTls, StartTls};
use libadb::Splittable;

#[path = "common/common.rs"]
mod common;

#[path = "fake_device/fake_device.rs"]
mod fake_device;

#[path = "rt/rt.rs"]
mod rt;

#[path = "test_key/test_key.rs"]
mod test_key;

/// What the fake device does with the certificate the host offers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyPolicy {
    /// Take any client certificate, the way a device that already
    /// trusts the key does.
    Accept,
    /// Refuse it. In TLS 1.3 the client's handshake still completes and
    /// the alert only reaches it on the first read.
    Reject,
}

fn host_key() -> AdbKey {
    AdbKey::from_pkcs8_pem(test_key::PKCS8_PEM, &mut OsRng, test_key::NAME).unwrap()
}

/// A device certificate, freshly minted. Wireless debugging does the
/// same: the pairing server generates one per run.
fn device_identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = AdbKey::generate(&mut OsRng, "device@fake").unwrap();
    let der = cert::build(&key, &mut OsRng).unwrap();
    let pkcs8 = key.to_pkcs8_der().unwrap();
    (
        CertificateDer::from(der),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec())),
    )
}

#[derive(Debug)]
struct ClientPolicy {
    accept: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for ClientPolicy {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.accept {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// What the fake device did, so a test can check the host's side of it.
struct DeviceReport {
    /// The public key inside the certificate the host offered, in DER.
    client_spki: Option<Vec<u8>>,
    /// Plaintext the host sent inside TLS.
    received: Vec<u8>,
    /// Whether the handshake completed on the device's side.
    handshake_ok: bool,
}

/// Start a device that demands TLS. It answers whatever the host sends
/// with the same bytes reversed, so a test can tell a real round trip
/// from an accident.
fn spawn_device(policy: KeyPolicy) -> (SocketAddr, JoinHandle<DeviceReport>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (cert, key) = device_identity();
        let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(ClientPolicy {
                accept: policy == KeyPolicy::Accept,
                provider,
            }))
            .with_single_cert(vec![cert], key)
            .unwrap();

        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);

        let mut report = DeviceReport {
            client_spki: None,
            received: Vec::new(),
            handshake_ok: false,
        };

        // The handshake runs on the first read.
        let mut buf = [0u8; 256];
        match tls.read(&mut buf) {
            Ok(n) => {
                report.handshake_ok = true;
                report.received.extend_from_slice(&buf[..n]);
                report.client_spki = tls
                    .conn
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| c.as_ref().to_vec());
                let mut echo: Vec<u8> = report.received.clone();
                echo.reverse();
                let _ = tls.write_all(&echo);
                let _ = tls.flush();
            }
            Err(_) => {
                report.handshake_ok = false;
            }
        }
        report
    });

    (addr, handle)
}

fn client_config() -> TlsClientConfig {
    let identity = TlsIdentity::from_key(&host_key(), &mut OsRng).unwrap();
    TlsClientConfig::adb(&identity).unwrap()
}

async fn connected(addr: SocketAddr) -> MaybeTls<rt::AdbTransport> {
    let stream = rt::connect(addr).await;
    let mut transport = MaybeTls::plain(rt::wrap(stream));
    transport.start_tls(&client_config(), &[]).await.unwrap();
    transport
}

rt_test! {
async fn a_tls_session_carries_plaintext_both_ways() {
    let (addr, device) = spawn_device(KeyPolicy::Accept);

    let mut transport = connected(addr).await;
    assert!(transport.is_tls(), "the transport reports the session it started");
    assert!(!transport.is_plain());

    transport.write(b"ping over tls").await.unwrap();
    transport.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = transport.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"slt revo gnip", "the device echoed it reversed");

    let report = device.join().unwrap();
    assert!(report.handshake_ok);
    assert_eq!(report.received, b"ping over tls");
}
}

rt_test! {
async fn the_device_is_shown_the_host_key_inside_the_certificate() {
    // This is the whole mechanism: adbd reads the public key out of the
    // client certificate and looks it up among the keys it trusts.
    let (addr, device) = spawn_device(KeyPolicy::Accept);

    let mut transport = connected(addr).await;
    transport.write(b"x").await.unwrap();
    transport.flush().await.unwrap();

    let report = device.join().unwrap();
    let offered = report.client_spki.expect("a client certificate was required");
    let expected = cert::build(&host_key(), &mut OsRng).unwrap();

    // The two certificates differ in their validity dates, so compare
    // the part the device actually looks at.
    assert_eq!(spki_of(&offered), spki_of(&expected));
}
}

rt_test! {
async fn a_rejected_key_surfaces_on_the_first_read_not_the_handshake() {
    // TLS 1.3 tells the client nothing when the server refuses its
    // certificate: the handshake completes locally and the alert
    // arrives with the first read. Anything built on this transport has
    // to expect that.
    let (addr, device) = spawn_device(KeyPolicy::Reject);

    let stream = rt::connect(addr).await;
    let mut transport = MaybeTls::plain(rt::wrap(stream));

    let handshake = transport.start_tls(&client_config(), &[]).await;
    let mut buf = [0u8; 64];
    let outcome = match handshake {
        // The usual case: the handshake "succeeded" and the refusal is
        // waiting in the stream.
        Ok(()) => transport.read(&mut buf).await.map(|_| ()),
        // Some timings surface it during the handshake instead.
        Err(e) => Err(e),
    };

    let Err(err) = outcome else {
        panic!("a device that refused the key must not hand out a working session");
    };
    assert!(
        err.is_key_rejected(),
        "the refusal must be recognised as one, got {err:?}"
    );
    let _ = device.join();
}
}

rt_test! {
async fn a_split_session_reads_and_writes_at_once() {
    let (addr, device) = spawn_device(KeyPolicy::Accept);

    let transport = connected(addr).await;
    let (mut reader, mut writer) = transport.split().unwrap();

    writer.write(b"split over tls").await.unwrap();
    writer.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"slt revo tilps");

    let report = device.join().unwrap();
    assert_eq!(report.received, b"split over tls");
}
}

rt_test! {
async fn a_plain_transport_still_splits_and_passes_bytes_through() {
    // Without an upgrade the wrapper must be invisible, because the
    // handshake runs through it before anyone knows whether the device
    // wants TLS at all.
    let (listener, addr) = rt::bind_loopback().await;
    let device = rt::spawn(async move {
        let mut socket = rt::accept_one(&listener).await;
        let mut buf = [0u8; 5];
        rt::read_exact(&mut socket, &mut buf).await;
        rt::write_all(&mut socket, b"pong!").await;
        buf
    });

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    assert!(transport.is_plain());
    let (mut reader, mut writer) = transport.split().unwrap();

    writer.write(b"ping!").await.unwrap();
    let mut buf = [0u8; 5];
    reader.read(&mut buf).await.unwrap();

    assert_eq!(&buf, b"pong!");
    assert_eq!(&rt::join(device).await, b"ping!");
}
}

/// The `subjectPublicKeyInfo` of a DER certificate, found by structure
/// rather than parsed: it is the only 290-byte SEQUENCE in an RSA-2048
/// certificate, and this test only needs to compare two of them.
fn spki_of(der: &[u8]) -> Vec<u8> {
    let needle = [0x30u8, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09];
    let at = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("an RSA-2048 SubjectPublicKeyInfo");
    der[at..at + 294].to_vec()
}

// ---------------------------------------------------------------------
// The whole handshake: STLS, then ADB inside the session
// ---------------------------------------------------------------------

use libadb::protocol::command::{CMD_CNXN, CMD_STLS};
use libadb::protocol::constant::{ADB_VERSION, STLS_VERSION};
use libadb::{Connection, Error};

const DEVICE_BANNER: &[u8] = b"device::features=shell_v2,cmd";

fn header(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(24 + payload.len());
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&arg0.to_le_bytes());
    h.extend_from_slice(&arg1.to_le_bytes());
    h.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let sum: u32 = payload.iter().map(|&b| b as u32).sum();
    h.extend_from_slice(&sum.to_le_bytes());
    h.extend_from_slice(&(command ^ 0xFFFF_FFFF).to_le_bytes());
    h.extend_from_slice(payload);
    h
}

fn read_packet(r: &mut impl std::io::Read) -> (u32, u32, u32, Vec<u8>) {
    let mut h = [0u8; 24];
    r.read_exact(&mut h).unwrap();
    let word = |i: usize| u32::from_le_bytes(h[i * 4..i * 4 + 4].try_into().unwrap());
    let len = word(3) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).unwrap();
    }
    (word(0), word(1), word(2), payload)
}

/// What the device saw the host do.
struct HandshakeReport {
    /// arg0 and arg1 of the host's own STLS.
    host_stls: (u32, u32),
    /// Whether the host's STLS carried a payload. AOSP's carries none.
    host_stls_payload: usize,
    /// Whether the host repeated its CNXN inside the session. It must
    /// not: the device speaks first there.
    repeated_cnxn: bool,
}

/// A device that demands TLS and then talks ADB inside it.
fn spawn_adb_device(policy: KeyPolicy) -> (SocketAddr, JoinHandle<HandshakeReport>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (cert, key) = device_identity();
        let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(ClientPolicy {
                accept: policy == KeyPolicy::Accept,
                provider,
            }))
            .with_single_cert(vec![cert], key)
            .unwrap();

        let (mut socket, _) = listener.accept().unwrap();

        // In the clear: the host's CNXN, then our demand for TLS.
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_CNXN, "the host opens with CNXN");
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();

        let (command, arg0, arg1, payload) = read_packet(&mut socket);
        assert_eq!(command, CMD_STLS, "the host answers STLS with STLS");
        let mut report = HandshakeReport {
            host_stls: (arg0, arg1),
            host_stls_payload: payload.len(),
            repeated_cnxn: false,
        };

        // From here on, TLS.
        let conn = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        // The device speaks first inside the session.
        if tls
            .write_all(&header(CMD_CNXN, ADB_VERSION, 256 * 1024, DEVICE_BANNER))
            .is_err()
        {
            return report;
        }
        let _ = tls.flush();

        // Nothing should arrive until the host opens a channel.
        tls.sock
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut probe = [0u8; 24];
        if let Ok(24) = tls.read(&mut probe) {
            report.repeated_cnxn = u32::from_le_bytes(probe[0..4].try_into().unwrap()) == CMD_CNXN;
        }
        report
    });

    (addr, handle)
}

rt_test! {
async fn a_device_that_demands_tls_ends_up_connected() {
    let (addr, device) = spawn_adb_device(KeyPolicy::Accept);

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let conn = Connection::<_>::connect_tls(
        transport,
        test_auth(),
        &[],
        &client_config(),
    )
    .await
    .expect("a device that offers TLS and trusts the key connects");

    assert!(conn.transport().is_tls(), "the session is running");
    assert_eq!(conn.device_banner(), Some(DEVICE_BANNER));

    let report = device.join().unwrap();
    assert_eq!(report.host_stls, (STLS_VERSION, 0), "the host mirrors the offer");
    assert_eq!(report.host_stls_payload, 0, "STLS carries no payload");
    assert!(!report.repeated_cnxn, "the host waits rather than repeating CNXN");
}
}

rt_test! {
async fn a_key_the_device_will_not_have_is_named_as_such() {
    let (addr, device) = spawn_adb_device(KeyPolicy::Reject);

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let Err(err) = Connection::<_>::connect_tls(
        transport,
        test_auth(),
        &[],
        &client_config(),
    )
    .await
    else {
        panic!("a device that refuses the key must not hand back a connection");
    };

    assert!(
        matches!(err, Error::Auth(libadb::error::AuthError::TlsKeyNotTrusted)),
        "expected TlsKeyNotTrusted, got {err:?}"
    );
    let _ = device.join();
}
}

rt_test! {
async fn a_device_that_never_asks_for_tls_is_served_in_the_clear() {
    // One entry point covers both kinds of device, so a caller does not
    // have to know which port it dialled.
    let (handle, addr) = fake_device::FakeDevice::new().bind().await;
    let device = rt::spawn(async move { handle.accept().await });

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let conn = Connection::<_>::connect_tls(
        transport,
        test_auth(),
        &[],
        &client_config(),
    )
    .await
    .expect("a plain device still connects");

    assert!(conn.transport().is_plain(), "nothing was upgraded");
    drop(device);
}
}

fn test_auth() -> AdbKey {
    host_key()
}

// ---------------------------------------------------------------------
// Against a real device, when one is offered
// ---------------------------------------------------------------------

/// Point `LIBADB_TLS_DEVICE` at a wireless-debugging port to run these:
///
/// ```text
/// LIBADB_TLS_DEVICE=192.168.1.5:41234 cargo test --features tokio,tls,host-keys --test tls
/// ```
///
/// They need a device whose store already holds `~/.android/adbkey`,
/// which is any device that has ever been authorised over USB. Without
/// the variable they do nothing, so CI is unaffected.
fn device_address() -> Option<SocketAddr> {
    std::env::var("LIBADB_TLS_DEVICE")
        .ok()?
        .parse()
        .map_err(|e| panic!("LIBADB_TLS_DEVICE is not an address: {e}"))
        .ok()
}

async fn real_device_key() -> AdbKey {
    let home = std::env::var("HOME").expect("HOME");
    let dir = std::path::PathBuf::from(home).join(".android");
    libadb::keys::store::load_or_generate(&dir, &mut OsRng, "libadb@test").unwrap()
}

rt_test! {
async fn a_real_device_serves_a_split_connection_over_tls() {
    let Some(addr) = device_address() else {
        return;
    };
    // The split halves are a code path of their own, with their own
    // locking, so a live device is worth the trouble here even though
    // the local server already covers the unsplit one.
    let key = real_device_key().await;
    let identity = TlsIdentity::from_key(&key, &mut OsRng).unwrap();
    let tls = TlsClientConfig::adb(&identity).unwrap();

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let conn = Connection::<_>::connect_tls(transport, key, &[], &tls)
        .await
        .expect("the device accepts a key it was shown over USB");
    assert!(conn.transport().is_tls());

    let (mut reader, _writer) = conn.split().expect("a TLS connection splits");

    // Enough output to cross many TLS records and many ADB packets.
    let ch = reader
        .open_channel(b"shell:seq 1 20000\0")
        .await
        .expect("the device opens a shell");

    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match reader.read_channel(ch, &mut buf).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(libadb::Error::ChannelClosed) => break,
            Err(e) => panic!("read over a split TLS session failed: {e:?}"),
        }
    }

    let lines = out
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    assert_eq!(lines, 20000, "every line survived the split TLS session");
}
}
