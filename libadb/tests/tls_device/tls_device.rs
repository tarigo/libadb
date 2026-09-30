//! The TLS side of a fake device, for the tests that need one: the key
//! the host proves itself with, the certificate the device mints for
//! itself, and a server configuration that takes or refuses the host.

#![allow(dead_code)]

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{cert, AdbKey};
use libadb::tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use libadb::tls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use libadb::tls::rustls::{DistinguishedName, ServerConfig};
use libadb::tls::{rustls, TlsClientConfig, TlsIdentity};

use crate::test_key;

/// Take the host's connection, with the timeouts a fake device needs:
/// a host that stops talking fails its test instead of hanging it.
pub fn accept(listener: &TcpListener) -> TcpStream {
    let (socket, _) = listener.accept().unwrap();
    let limit = Some(Duration::from_secs(5));
    socket.set_read_timeout(limit).unwrap();
    socket.set_write_timeout(limit).unwrap();
    socket
}

/// The host's key: the one a USB prompt would have approved.
pub fn host_key() -> AdbKey {
    AdbKey::from_pkcs8_pem(test_key::PKCS8_PEM, &mut OsRng, test_key::NAME).unwrap()
}

/// The profile the host connects and pairs with, carrying [`host_key`].
pub fn client_config() -> TlsClientConfig {
    let identity = TlsIdentity::from_key(&host_key(), &mut OsRng).unwrap();
    TlsClientConfig::adb(&identity).unwrap()
}

/// What the fake device does with the certificate the host offers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyPolicy {
    /// Take any client certificate, the way a device that already
    /// trusts the key does.
    Accept,
    /// Refuse it. In TLS 1.3 the client's handshake still completes and
    /// the alert only reaches it on the first read.
    Reject,
}

/// A device certificate, freshly minted. Wireless debugging does the
/// same: the pairing server generates one per run.
pub fn device_identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
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
    /// How many client certificates the device has been shown.
    shown: Arc<AtomicUsize>,
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
        self.shown.fetch_add(1, Ordering::Relaxed);
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

/// The device's side of TLS 1.3, taking or refusing the host's key.
pub fn device_config(policy: KeyPolicy) -> Arc<ServerConfig> {
    device_config_counting(policy, Arc::default())
}

/// [`device_config`], counting in `shown` the certificates it checks.
pub fn device_config_counting(policy: KeyPolicy, shown: Arc<AtomicUsize>) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (cert, key) = device_identity();
    let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(ClientPolicy {
            accept: policy == KeyPolicy::Accept,
            provider,
            shown,
        }))
        .with_single_cert(vec![cert], key)
        .unwrap();
    Arc::new(config)
}
