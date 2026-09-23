//! The self-signed certificate an ADB host presents over TLS.
//!
//! Wireless debugging authenticates the host by the public key inside
//! its client certificate, checked against the same trusted-key store
//! that a USB authorisation prompt fills. So the certificate carries no
//! secret of its own: it is a wrapper that lets an [`AdbKey`] travel
//! through a TLS handshake.
//!
//! The shape follows AOSP's `crypto/x509_generator.cpp` field for
//! field. A device only compares the public key, but matching what
//! `adb` emits keeps us out of any future tightening.

use alloc::vec::Vec;
use std::time::{Duration, SystemTime};

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::EncodePublicKey;
use rsa::rand_core::CryptoRngCore;
use rsa::sha2::{Digest, Sha256};
use sha1::Sha1;
use x509_cert::der::asn1::{BitString, Null, OctetString, UtcTime};
use x509_cert::der::{Any, Encode};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

use super::AdbKey;

/// `sha256WithRSAEncryption`, the algorithm `adb` signs with.
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// How long the certificate stays valid. AOSP uses ten 365-day years.
const LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

/// Subject and issuer, in the order AOSP writes them.
const DISTINGUISHED_NAME: &str = "CN=Adb,O=Android,C=US";

/// Why a certificate could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum CertError {
    /// Encoding or decoding an ASN.1 structure failed.
    Der(x509_cert::der::Error),
    /// The public key would not round-trip through SPKI.
    Spki(x509_cert::spki::Error),
    /// Signing the certificate body failed.
    Rsa(rsa::Error),
    /// The clock reads a time no certificate can carry: before the Unix
    /// epoch, or so late that the validity would run past the year 9999.
    Clock,
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(e) => write!(f, "certificate encoding: {e}"),
            Self::Spki(e) => write!(f, "certificate public key: {e}"),
            Self::Rsa(e) => write!(f, "certificate signature: {e}"),
            Self::Clock => f.write_str("system clock is outside what a certificate can carry"),
        }
    }
}

impl core::error::Error for CertError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Der(e) => Some(e),
            Self::Spki(e) => Some(e),
            Self::Rsa(e) => Some(e),
            Self::Clock => None,
        }
    }
}

impl From<x509_cert::der::Error> for CertError {
    fn from(e: x509_cert::der::Error) -> Self {
        Self::Der(e)
    }
}

impl From<x509_cert::spki::Error> for CertError {
    fn from(e: x509_cert::spki::Error) -> Self {
        Self::Spki(e)
    }
}

/// Build the self-signed certificate for `key`, valid from now.
///
/// Returns DER, which is what a TLS stack wants.
pub fn build<R: CryptoRngCore>(key: &AdbKey, rng: &mut R) -> Result<Vec<u8>, CertError> {
    build_at(key, rng, SystemTime::now())
}

/// [`build`], with `not_before` supplied rather than read from the
/// clock, so a test can compare bytes against a fixed expectation.
pub fn build_at<R: CryptoRngCore>(
    key: &AdbKey,
    rng: &mut R,
    not_before: SystemTime,
) -> Result<Vec<u8>, CertError> {
    let name: Name = DISTINGUISHED_NAME.parse()?;
    let algorithm = AlgorithmIdentifierOwned {
        oid: SHA256_WITH_RSA,
        // An explicit NULL, not an absent parameter: RFC 4055 section 5.
        parameters: Some(Any::from(Null)),
    };

    let spki_der = key.private_key().to_public_key().to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::try_from(spki_der.as_bytes())?;

    let not_after = not_before.checked_add(LIFETIME).ok_or(CertError::Clock)?;
    let validity = Validity {
        not_before: rfc5280_time(not_before)?,
        not_after: rfc5280_time(not_after)?,
    };

    let extensions = extensions(&name, &spki)?;

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01])?,
        signature: algorithm.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    let tbs_der = tbs.to_der()?;
    let digest = Sha256::digest(&tbs_der);
    // `sign_with_rng`, not `sign`: private-key operations here are blinded.
    let signature = key
        .private_key()
        .sign_with_rng(rng, Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(CertError::Rsa)?;

    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature)?,
    };
    Ok(certificate.to_der()?)
}

/// A timestamp as RFC 5280 section 4.1.2.5 wants it: `UTCTime` through
/// 2049, `GeneralizedTime` after. `x509-cert` hands out the latter for
/// everything, which `adb` does not and a strict verifier may refuse.
fn rfc5280_time(at: SystemTime) -> Result<Time, CertError> {
    // Its only failure is a time outside 1970 to 9999, which `x509-cert`
    // reports as an encoding error; the cause is the clock.
    let time = Time::try_from(at).map_err(|_| CertError::Clock)?;
    if let Time::GeneralTime(t) = time {
        let date = t.to_date_time();
        if date.year() <= UtcTime::MAX_YEAR {
            return Ok(Time::UtcTime(UtcTime::from_date_time(date)?));
        }
    }
    Ok(time)
}

/// The three extensions AOSP puts on the certificate.
fn extensions(name: &Name, spki: &SubjectPublicKeyInfoOwned) -> Result<Vec<Extension>, CertError> {
    let mut out = Vec::with_capacity(3);

    let basic = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    out.push(basic.to_extension(name, &out)?);

    let usage = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyCertSign | KeyUsages::CRLSign);
    out.push(usage.to_extension(name, &out)?);

    // `subjectKeyIdentifier = hash` in OpenSSL terms: SHA-1 of the key bits.
    let key_id = Sha1::digest(spki.subject_public_key.raw_bytes());
    let skid = SubjectKeyIdentifier(OctetString::new(key_id.as_slice())?);
    out.push(skid.to_extension(name, &out)?);

    Ok(out)
}
