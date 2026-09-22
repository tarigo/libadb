//! The pairing exchange against a device that plays its part.
//!
//! The device side runs blocking on its own thread over `rustls`' own
//! stream, and drives the protocol by hand. It shares the SPAKE2
//! primitive with the client, which is the one piece that cannot be
//! written twice here; that primitive is pinned separately against
//! vectors from an implementation written from the BoringSSL source.
//! Everything around it — the exporter, the framing, the cipher, the
//! `PeerInfo` — the two sides reach independently.

#![cfg(all(feature = "pairing", any(feature = "tokio", feature = "smol")))]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::JoinHandle;

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{cert, AdbKey};
use libadb::pairing::{pair, PairingError, Role, Spake2};
use libadb::tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use libadb::tls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use libadb::tls::rustls::{DistinguishedName, ServerConfig, ServerConnection, StreamOwned};
use libadb::tls::{rustls, TlsClientConfig, TlsIdentity};
use libadb::transport::tls::MaybeTls;

#[path = "common/common.rs"]
mod common;

#[path = "fake_device/fake_device.rs"]
mod fake_device;

#[path = "rt/rt.rs"]
mod rt;

#[path = "test_key/test_key.rs"]
mod test_key;

const EXPORTER_LABEL: &[u8] = b"adb-label\0";
const CLIENT_NAME: &[u8] = b"adb pair client\0";
const SERVER_NAME: &[u8] = b"adb pair server\0";
const DEVICE_GUID: &str = "adb-fake-device-guid";

fn host_key() -> AdbKey {
    AdbKey::from_pkcs8_pem(test_key::PKCS8_PEM, &mut OsRng, test_key::NAME).unwrap()
}

#[derive(Debug)]
struct AcceptAnyClient {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for AcceptAnyClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
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

/// What the device came away with.
#[derive(Debug, Default)]
struct DeviceOutcome {
    /// The public key the host offered, as the device read it.
    learned_key: Option<String>,
    /// Whether the device could open the host's message at all.
    opened: bool,
}

/// A device serving its pairing port, with `code` on its screen.
fn spawn_pairing_device(code: &'static str) -> (SocketAddr, JoinHandle<DeviceOutcome>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // The pairing server mints a throwaway certificate per run.
        let key = AdbKey::generate(&mut OsRng, "device@fake").unwrap();
        let der = cert::build(&key, &mut OsRng).unwrap();
        let pkcs8 = key.to_pkcs8_der().unwrap();
        let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(AcceptAnyClient { provider }))
            .with_single_cert(
                vec![CertificateDer::from(der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec())),
            )
            .unwrap();

        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        let mut outcome = DeviceOutcome::default();

        // Reading drives the handshake to completion, which the
        // exporter needs.
        let mut header = [0u8; 6];
        if tls.read_exact(&mut header).is_err() {
            return outcome;
        }

        let mut exported = [0u8; 64];
        tls.conn
            .export_keying_material(&mut exported, EXPORTER_LABEL, None)
            .unwrap();
        let mut password = code.as_bytes().to_vec();
        password.extend_from_slice(&exported);

        // The host's SPAKE2 message, whose header we already have.
        assert_eq!(header, [1, 0, 0, 0, 0, 32], "a 32-byte SPAKE2 packet");
        let mut theirs = [0u8; 32];
        tls.read_exact(&mut theirs).unwrap();

        let spake2 = Spake2::new(Role::Bob, SERVER_NAME, CLIENT_NAME, &password, &mut OsRng);
        tls.write_all(&frame(0, spake2.message())).unwrap();
        tls.flush().unwrap();

        let key_material = spake2.finish(&theirs).unwrap();
        let mut cipher = DeviceCipher::new(&key_material[..]);

        // adbd sends its half before it reads ours. That order is what
        // lets a host tell a wrong code apart from a device that quit:
        // the block arrives, and will not open.
        let mut answer = vec![0u8; 8192];
        answer[0] = 1;
        answer[1..1 + DEVICE_GUID.len()].copy_from_slice(DEVICE_GUID.as_bytes());
        let sealed = cipher.seal(&answer);
        tls.write_all(&frame(1, &sealed)).unwrap();
        tls.flush().unwrap();

        let mut header = [0u8; 6];
        if tls.read_exact(&mut header).is_err() {
            return outcome;
        }
        let len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
        let mut sealed = vec![0u8; len];
        tls.read_exact(&mut sealed).unwrap();

        if let Ok(block) = cipher.open(&sealed) {
            outcome.opened = true;
            assert_eq!(block.len(), 8192, "the host pads to the full size");
            assert_eq!(block[0], 0, "type 0 is an RSA public key");
            let end = block[1..].iter().position(|&b| b == 0).unwrap();
            outcome.learned_key = Some(String::from_utf8(block[1..1 + end].to_vec()).unwrap());
        }
        // A device that could not read the block has nothing more to say.
        outcome
    });

    (addr, handle)
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8, kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The device's own cipher, written out here rather than borrowed, so
/// the nonce and the key derivation are agreed on twice.
struct DeviceCipher {
    key: aes_gcm::Aes128Gcm,
    encrypt_counter: u64,
    decrypt_counter: u64,
}

impl DeviceCipher {
    fn new(key_material: &[u8]) -> Self {
        use aes_gcm::KeyInit;
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, key_material);
        let mut key = [0u8; 16];
        hk.expand(b"adb pairing_auth aes-128-gcm key", &mut key)
            .unwrap();
        Self {
            key: aes_gcm::Aes128Gcm::new(&key.into()),
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }

    fn nonce(counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&counter.to_le_bytes());
        n
    }

    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::Aead;
        let n = Self::nonce(self.encrypt_counter);
        self.encrypt_counter += 1;
        self.key
            .encrypt(aes_gcm::Nonce::from_slice(&n), plaintext)
            .unwrap()
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        use aes_gcm::aead::Aead;
        let n = Self::nonce(self.decrypt_counter);
        let out = self
            .key
            .decrypt(aes_gcm::Nonce::from_slice(&n), ciphertext)
            .map_err(|_| ())?;
        self.decrypt_counter += 1;
        Ok(out)
    }
}

async fn client(addr: SocketAddr) -> MaybeTls<rt::AdbTransport> {
    MaybeTls::plain(rt::wrap(rt::connect(addr).await))
}

fn tls_config() -> TlsClientConfig {
    let identity = TlsIdentity::from_key(&host_key(), &mut OsRng).unwrap();
    TlsClientConfig::adb(&identity).unwrap()
}

rt_test! {
async fn the_right_code_hands_the_device_our_key() {
    let (addr, device) = spawn_pairing_device("592781");
    let key = host_key();

    let paired = pair(
        &mut client(addr).await,
        &tls_config(),
        &key,
        "592781",
        &mut OsRng,
    )
    .await
    .expect("a matching code pairs");

    assert_eq!(paired.guid, DEVICE_GUID);

    let outcome = device.join().unwrap();
    assert!(outcome.opened, "the device could read what we sent");
    assert_eq!(
        outcome.learned_key.unwrap().as_bytes(),
        key.public_key_line(),
        "the device learned the same key a USB prompt would have approved"
    );
}
}

rt_test! {
async fn a_wrong_code_is_reported_as_such_and_gives_nothing_away() {
    let (addr, device) = spawn_pairing_device("592781");

    let outcome = pair(
        &mut client(addr).await,
        &tls_config(),
        &host_key(),
        "000000",
        &mut OsRng,
    )
    .await;

    let Err(err) = outcome else {
        panic!("a wrong code must not pair");
    };
    assert!(
        matches!(err, PairingError::WrongCode),
        "expected WrongCode, got {err:?}"
    );

    let device = device.join().unwrap();
    assert!(!device.opened, "the device learned nothing");
    assert!(device.learned_key.is_none());
}
}
