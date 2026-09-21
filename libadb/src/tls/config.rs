//! The `rustls` profile an ADB host connects with.

use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use super::TlsIdentity;

/// What the certificate is nominally issued to. The device never checks
/// it, and SNI is switched off, so it never reaches the wire either.
const PLACEHOLDER_SERVER_NAME: &str = "adb";

/// Why a client profile could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsConfigError {
    /// `rustls` refused the configuration, usually the client key.
    Rustls(rustls::Error),
}

impl core::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rustls(e) => write!(f, "tls configuration: {e}"),
        }
    }
}

impl core::error::Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Rustls(e) => Some(e),
        }
    }
}

/// A ready-to-use `rustls` client profile plus the name to offer it
/// under.
#[derive(Clone, Debug)]
pub struct TlsClientConfig {
    inner: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl TlsClientConfig {
    /// The profile `adb` uses: TLS 1.3 only, the `ring` provider, the
    /// client certificate from `identity`, and a device certificate
    /// taken on trust.
    ///
    /// # Security
    ///
    /// The device is not authenticated. Its certificate is self-signed
    /// and chains to nothing, so neither the chain nor the name is
    /// checked — AOSP's client does the same. The signature in
    /// `CertificateVerify` still is, which proves the peer holds the
    /// key in the certificate it offered but says nothing about who
    /// that peer is. On a network you do not trust, an attacker in the
    /// middle can take the device's place, exactly as with `adb`.
    pub fn adb(identity: &TlsIdentity) -> Result<Self, TlsConfigError> {
        // Spelled out, not defaulted: a feature-unified build may switch on
        // `tls12` or another provider, and a default would follow it.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (chain, key) = identity.rustls_parts();

        let mut inner = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(TlsConfigError::Rustls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyDevice { provider }))
            .with_client_auth_cert(chain, key)
            .map_err(TlsConfigError::Rustls)?;
        // adbd ignores SNI; sending one would only differ from `adb`.
        inner.enable_sni = false;

        Ok(Self {
            inner: Arc::new(inner),
            server_name: ServerName::try_from(PLACEHOLDER_SERVER_NAME)
                .expect("a bare DNS label is a valid server name"),
        })
    }

    /// Build a profile from a `rustls` configuration of your own, for
    /// callers who want to pin the device certificate or otherwise
    /// tighten what [`adb`](Self::adb) leaves open.
    pub fn from_rustls(config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Self {
        Self {
            inner: config,
            server_name,
        }
    }

    /// The configuration underneath.
    pub fn rustls(&self) -> &Arc<ClientConfig> {
        &self.inner
    }

    pub(crate) fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }
}

/// Takes any device certificate, the way AOSP's client does.
///
/// The signature check is kept: it costs nothing and proves the peer
/// holds the private key for the certificate it sent.
#[derive(Debug)]
struct AcceptAnyDevice {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyDevice {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Only TLS 1.3 was offered.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
