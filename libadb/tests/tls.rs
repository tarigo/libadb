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
use libadb::transport::tls::{MaybeTls, StartTls, TlsError};
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
        matches!(err, TlsError::Tls(_) | TlsError::HandshakeClosed | TlsError::Io(_)),
        "expected a TLS-level refusal, got {err:?}"
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
