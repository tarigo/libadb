//! The certificate and key a host presents to a device over TLS.

use alloc::vec;
use alloc::vec::Vec;
use std::time::SystemTime;

use rsa::pkcs8::EncodePrivateKey;
use rsa::rand_core::CryptoRngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::keys::cert::{self, CertError};
use crate::keys::AdbKey;

/// Why an identity could not be built from a key.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsIdentityError {
    /// The certificate could not be built or signed.
    Certificate(CertError),
    /// The private key could not be encoded as PKCS#8.
    PrivateKey(rsa::pkcs8::Error),
}

impl core::fmt::Display for TlsIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Certificate(e) => write!(f, "tls identity certificate: {e}"),
            Self::PrivateKey(e) => write!(f, "tls identity private key: {e}"),
        }
    }
}

impl core::error::Error for TlsIdentityError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Certificate(e) => Some(e),
            // `pkcs8::Error` implements the error trait only with std.
            Self::PrivateKey(_) => None,
        }
    }
}

/// What the host proves itself with over TLS: a self-signed certificate
/// carrying an [`AdbKey`]'s public key, and that key to sign with.
///
/// Building one is the expensive part of a TLS connection — it signs a
/// certificate — so build it once and lend it to every connection.
///
/// Pairing over `adb pair` needs the same material, which is why this
/// is not hidden inside the transport.
pub struct TlsIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivatePkcs8KeyDer<'static>,
}

impl TlsIdentity {
    /// Build the identity `key` presents, valid from now.
    pub fn from_key<R: CryptoRngCore>(key: &AdbKey, rng: &mut R) -> Result<Self, TlsIdentityError> {
        Self::from_key_at(key, rng, SystemTime::now())
    }

    /// [`from_key`](Self::from_key) with the certificate's start date
    /// supplied rather than read from the clock.
    pub fn from_key_at<R: CryptoRngCore>(
        key: &AdbKey,
        rng: &mut R,
        not_before: SystemTime,
    ) -> Result<Self, TlsIdentityError> {
        let certificate =
            cert::build_at(key, rng, not_before).map_err(TlsIdentityError::Certificate)?;
        let pkcs8 = key
            .private_key()
            .to_pkcs8_der()
            .map_err(TlsIdentityError::PrivateKey)?;

        Ok(Self {
            certificate: CertificateDer::from(certificate),
            private_key: PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
        })
    }

    /// The certificate in DER, for a caller that wants to inspect or
    /// publish it.
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// The chain and key in the shape `rustls` asks for.
    pub(crate) fn rustls_parts(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![self.certificate.clone()],
            PrivateKeyDer::Pkcs8(self.private_key.clone_key()),
        )
    }
}

impl core::fmt::Debug for TlsIdentity {
    /// Never prints the private key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("certificate_len", &self.certificate.as_ref().len())
            .finish_non_exhaustive()
    }
}
