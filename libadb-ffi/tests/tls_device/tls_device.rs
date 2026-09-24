//! The device side of ADB over TLS, for driving the C entry points: a
//! fake adbd that demands STLS and then talks ADB inside the session.
//!
//! Written blocking, on its own thread, over `rustls`' own stream — a
//! different style from the transport under test on purpose: an oracle
//! that reuses the code it is checking proves nothing.

#![allow(dead_code)]

use std::ffi::CString;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;

use libadb::keys::rsa::pkcs8::EncodePublicKey as _;
use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{cert, AdbKey};
use libadb::tls::rustls;
use libadb::tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use libadb::tls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use libadb::tls::rustls::{DistinguishedName, ServerConfig, ServerConnection, StreamOwned};

use crate::common::{
    header, read_packet, CMD_CLSE, CMD_CNXN, CMD_OKAY, CMD_OPEN, CMD_STLS, CMD_WRTE, MAX_PAYLOAD,
    STLS_VERSION, VERSION,
};

/// The TLS session as the device holds it.
pub type TlsStream = StreamOwned<ServerConnection, TcpStream>;

/// The device thread's result: what it saw, and what `inside` gave
/// back if the session got that far.
pub type Served<R> = JoinHandle<(Report, Option<R>)>;

/// The key a test connects with, in the forms the C API and the device
/// each want: the PEM and the public line for `adb_connect`, and the
/// DER `SubjectPublicKeyInfo` the device looks for in the certificate.
pub struct HostKey {
    pub pem: CString,
    pub public: CString,
    pub spki: Vec<u8>,
}

impl HostKey {
    fn generate() -> Self {
        let key = AdbKey::generate(&mut OsRng, "unit@test").unwrap();
        let pem = CString::new(key.to_pkcs8_pem().unwrap().as_str()).unwrap();
        let public = CString::new(key.public_key_line()).unwrap();
        let spki = key
            .private_key()
            .to_public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        Self { pem, public, spki }
    }
}

/// One host key per test binary: generating one is the slow part, and
/// the tests only need a key the device can be told to trust or refuse.
pub fn host_key() -> &'static HostKey {
    static KEY: OnceLock<HostKey> = OnceLock::new();
    KEY.get_or_init(HostKey::generate)
}

/// What the device does with the certificate the host offers.
#[derive(Debug, Clone)]
pub enum KeyPolicy {
    /// Trust exactly the key whose DER `SubjectPublicKeyInfo` this is,
    /// the way adbd checks a certificate against its store.
    Trust(Vec<u8>),
    /// Refuse whatever comes. In TLS 1.3 the client's handshake still
    /// completes and the refusal only reaches it on the first read.
    Reject,
}

/// What the device saw, for a test to check the host's side of it.
pub struct Report {
    /// arg0 of the host's own STLS.
    pub host_stls_version: u32,
    /// Whether the device turned the host's certificate down.
    pub refused_key: bool,
}

/// The device's own certificate, minted once per test binary.
fn device_identity() -> &'static (CertificateDer<'static>, PrivateKeyDer<'static>) {
    static IDENTITY: OnceLock<(CertificateDer<'static>, PrivateKeyDer<'static>)> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let key = AdbKey::generate(&mut OsRng, "device@fake").unwrap();
        let der = cert::build(&key, &mut OsRng).unwrap();
        let pkcs8 = key.to_pkcs8_der().unwrap();
        (
            CertificateDer::from(der),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec())),
        )
    })
}

#[derive(Debug)]
struct ClientPolicy {
    policy: KeyPolicy,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for ClientPolicy {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let trusted = match &self.policy {
            // The SPKI is one contiguous SEQUENCE inside the
            // certificate's DER, so it can be found without parsing.
            KeyPolicy::Trust(spki) => end_entity
                .as_ref()
                .windows(spki.len())
                .any(|window| window == spki),
            KeyPolicy::Reject => false,
        };
        if trusted {
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

/// The device's side of TLS 1.3, taking or refusing the host's key.
fn device_config(policy: KeyPolicy) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (cert, key) = device_identity();
    let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(ClientPolicy { policy, provider }))
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .unwrap();
    Arc::new(config)
}

/// Whether a device-side failure was its own verifier turning the
/// host's certificate down, rather than anything else going wrong.
fn refused_the_key(error: &std::io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidCertificate(_))
    )
}

/// Start a device that demands TLS, then hands the session to `inside`
/// once its own CNXN is out: the ADB spoken from there is the closure's
/// to write. It is told whether delayed ack was negotiated, and never
/// runs when the device refused the key.
pub fn spawn_with<F, R>(policy: KeyPolicy, inside: F) -> (String, Served<R>)
where
    F: FnOnce(&mut TlsStream, bool) -> R + Send + 'static,
    R: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let handle = std::thread::spawn(move || {
        let config = device_config(policy);
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_nodelay(true).unwrap();

        // In the clear: the host's CNXN, then the demand for TLS.
        let (cmd, _, payload) = read_packet(&mut socket).expect("the host opens with CNXN");
        assert_eq!(cmd, CMD_CNXN, "the host opens with CNXN");
        let feature = b"delayed_ack";
        let delayed_ack = payload.windows(feature.len()).any(|w| w == feature);
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();

        let (cmd, host_stls_version, _) = read_packet(&mut socket).expect("the host answers STLS");
        assert_eq!(cmd, CMD_STLS, "the host answers STLS with STLS");

        // From here on, TLS. The device speaks first inside the session,
        // and a refused key shows up as that first write failing.
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        let banner = b"device::features=shell_v2,delayed_ack";
        if let Err(e) = tls.write_all(&header(CMD_CNXN, VERSION, MAX_PAYLOAD, banner)) {
            let report = Report {
                host_stls_version,
                refused_key: refused_the_key(&e),
            };
            return (report, None);
        }
        let _ = tls.flush();

        let served = inside(&mut tls, delayed_ack);
        let report = Report {
            host_stls_version,
            refused_key: false,
        };
        (report, Some(served))
    });

    (addr, handle)
}

/// Serve one channel: OPEN is granted, `pushes` go out as one WRTE
/// each, every WRTE from the host is recorded and acknowledged, CLSE
/// ends it. Returns what the host wrote.
pub fn serve_channel(tls: &mut TlsStream, delayed_ack: bool, pushes: &[Vec<u8>]) -> Vec<u8> {
    let mut written = Vec::new();
    let mut remote_id = 0u32;
    while let Some((cmd, arg0, payload)) = read_packet(tls) {
        match cmd {
            CMD_OPEN => {
                remote_id = arg0;
                // In delayed-ack mode the OKAY that answers OPEN carries
                // the writer's initial budget.
                let budget = 1_000_000u32.to_le_bytes();
                let credit: &[u8] = if delayed_ack { &budget } else { &[] };
                tls.write_all(&header(CMD_OKAY, 1, remote_id, credit))
                    .unwrap();
                for push in pushes {
                    tls.write_all(&header(CMD_WRTE, 1, remote_id, push))
                        .unwrap();
                }
                tls.flush().unwrap();
            }
            CMD_WRTE => {
                // Acknowledged the way adbd does it: with the bytes
                // consumed as credit when delayed ack is on.
                let consumed = (payload.len() as u32).to_le_bytes();
                let credit: &[u8] = if delayed_ack { &consumed } else { &[] };
                written.extend_from_slice(&payload);
                tls.write_all(&header(CMD_OKAY, 1, remote_id, credit))
                    .unwrap();
                tls.flush().unwrap();
            }
            CMD_CLSE => {
                tls.write_all(&header(CMD_CLSE, 1, remote_id, &[])).unwrap();
                let _ = tls.flush();
                break;
            }
            _ => {}
        }
    }
    written
}

/// A device that demands TLS and then serves one channel.
pub fn spawn(policy: KeyPolicy, pushes: Vec<Vec<u8>>) -> (String, Served<Vec<u8>>) {
    spawn_with(policy, move |tls, delayed_ack| {
        serve_channel(tls, delayed_ack, &pushes)
    })
}

/// A device that asks for TLS, reads the ClientHello and hangs up, long
/// before the host's certificate could have reached it.
pub fn spawn_hanging_up_mid_handshake() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (cmd, _, _) = read_packet(&mut socket).expect("the host opens with CNXN");
        assert_eq!(cmd, CMD_CNXN, "the host opens with CNXN");
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();
        let (cmd, _, _) = read_packet(&mut socket).expect("the host answers STLS");
        assert_eq!(cmd, CMD_STLS, "the host answers STLS with STLS");

        // All of the ClientHello record, so the close is a clean FIN
        // rather than a reset over unread bytes.
        let mut head = [0u8; 5];
        socket.read_exact(&mut head).unwrap();
        let mut hello = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
        socket.read_exact(&mut hello).unwrap();
    });

    (addr, handle)
}
