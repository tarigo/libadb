//! ADB host key material: RSA-2048 generation, PKCS#8 import/export
//! and the mincrypt public-key format used in the AUTH handshake.
//!
//! ADB authenticates the host with an RSA-2048 key. The device receives
//! the public half in a bespoke format inherited from mincrypt: a
//! 524-byte struct (word count, Montgomery `n0inv`, little-endian
//! modulus, `R^2 mod n`, exponent), base64-encoded and followed by a
//! ` user@host` comment. That is the line `adb keygen` writes to
//! `adbkey.pub` and the payload of the `AUTH(RSAPUBLICKEY)` packet.
//!
//! This module produces and consumes exactly those shapes without any
//! `adb` installation. It is `no_std + alloc`: entropy arrives as a
//! parameter, and no platform source of it is opened here — a key
//! seeds its own blinding generator from what the caller supplies, so
//! nothing drags in `getrandom` behind your back.

pub(crate) mod pubkey;
mod record;
#[cfg(feature = "host-keys")]
pub mod store;

#[cfg(test)]
mod tests;

pub use pubkey::encode_public_key;
pub use record::{decode_key_record, encode_key_record};

// The public API speaks these crates' types, so a caller names the
// versions this crate resolved instead of guessing them in its own.
pub use rsa;
pub use zeroize;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;

use rand_chacha::ChaCha12Rng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding, SecretDocument};
use rsa::rand_core::{CryptoRngCore, SeedableRng};
use rsa::RsaPrivateKey;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::auth::Authenticator;

/// Modulus size ADB fixes its public-key format at.
const MODULUS_BITS: usize = 2048;

/// Length of the SHA-1 prehash adbd issues as an AUTH token.
const TOKEN_LEN: usize = 20;

/// An ADB host key: signs AUTH tokens and carries the public half in
/// the format the device expects.
///
/// The signing parameters are built once and the public-key blob is
/// encoded once, so a handshake costs a single RSA operation. That
/// operation is *blinded*, which is why the key owns a CSPRNG of its
/// own: the token it signs is chosen by whatever it is talking to, and
/// an unmasked private-key operation leaks timing to that peer.
///
/// A single key can drive several connections: `Connection::connect`
/// takes the authenticator by value, and `&mut AdbKey` is one too, so
/// pass `&mut key` rather than rebuilding — or cloning — the secret.
pub struct AdbKey {
    key: RsaPrivateKey,
    padding: Pkcs1v15Sign,
    blinding: ChaCha12Rng,
    public_key_wire: Vec<u8>,
}

impl AdbKey {
    /// Generate a fresh RSA-2048 key (`e = 65537`) from `rng`.
    ///
    /// The caller supplies the CSPRNG: on a host that is typically
    /// `OsRng`, on a microcontroller a hardware TRNG. Generation takes
    /// seconds on a desktop and minutes on a small microcontroller, so
    /// persist the result rather than repeating it.
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R, name: &str) -> Result<Self, KeyError> {
        // The name is cheap to reject; the key that follows is not.
        pubkey::validate_name(name)?;
        let key = RsaPrivateKey::new(rng, MODULUS_BITS).map_err(KeyError::Rsa)?;
        Self::from_private_key(key, rng, name)
    }

    /// Load a key from PKCS#8 PEM — the `~/.android/adbkey` format.
    pub fn from_pkcs8_pem<R: CryptoRngCore + ?Sized>(
        pem: &str,
        rng: &mut R,
        name: &str,
    ) -> Result<Self, KeyError> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(KeyError::Pkcs8)?;
        Self::from_private_key(key, rng, name)
    }

    /// Load a key from PKCS#1 PEM — what `adb` wrote before it moved to
    /// PKCS#8, and what `openssl genrsa -traditional` still writes.
    pub fn from_pkcs1_pem<R: CryptoRngCore + ?Sized>(
        pem: &str,
        rng: &mut R,
        name: &str,
    ) -> Result<Self, KeyError> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem).map_err(KeyError::Pkcs1)?;
        Self::from_private_key(key, rng, name)
    }

    /// Load a key from PKCS#8 DER, e.g. one held in flash.
    pub fn from_pkcs8_der<R: CryptoRngCore + ?Sized>(
        der: &[u8],
        rng: &mut R,
        name: &str,
    ) -> Result<Self, KeyError> {
        let key = RsaPrivateKey::from_pkcs8_der(der).map_err(KeyError::Pkcs8)?;
        Self::from_private_key(key, rng, name)
    }

    /// Export as PKCS#8 PEM, the shape `adb keygen` writes. The buffer
    /// zeroizes on drop.
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, KeyError> {
        self.key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(KeyError::Pkcs8)
    }

    /// Export as PKCS#8 DER. The document zeroizes on drop.
    pub fn to_pkcs8_der(&self) -> Result<SecretDocument, KeyError> {
        self.key.to_pkcs8_der().map_err(KeyError::Pkcs8)
    }

    /// The `AUTH(RSAPUBLICKEY)` payload: the public-key line plus the
    /// terminating NUL adbd expects.
    pub fn public_key_wire(&self) -> &[u8] {
        &self.public_key_wire
    }

    /// The same key without that NUL — the line to write into
    /// `adbkey.pub`, where `adb` puts no terminator.
    pub fn public_key_line(&self) -> &[u8] {
        &self.public_key_wire[..self.public_key_wire.len() - 1]
    }

    /// The private key, for callers that need the `rsa` type directly.
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.key
    }

    fn from_private_key<R: CryptoRngCore + ?Sized>(
        key: RsaPrivateKey,
        rng: &mut R,
        name: &str,
    ) -> Result<Self, KeyError> {
        let mut public_key_wire = encode_public_key(&key.to_public_key(), name)?;
        public_key_wire.push(b'\0');

        // Blinding needs entropy per signature and `sign` takes no RNG,
        // so the key seeds one of its own from the caller's.
        let mut seed = <ChaCha12Rng as SeedableRng>::Seed::default();
        rng.fill_bytes(&mut seed);

        Ok(Self {
            key,
            padding: Pkcs1v15Sign::new::<Sha1>(),
            blinding: ChaCha12Rng::from_seed(seed),
            public_key_wire,
        })
    }
}

impl fmt::Debug for AdbKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rsa` derives Debug over its private fields, so forwarding
        // the key to a formatter would print `d` and the primes.
        f.debug_struct("AdbKey")
            .field(
                "public_key",
                &String::from_utf8_lossy(self.public_key_line()),
            )
            .finish_non_exhaustive()
    }
}

impl Authenticator for AdbKey {
    type Error = KeyError;

    fn sign(&mut self, token: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        // `rsa` pads whatever it is handed, and a stray length becomes a
        // DigestInfo no device accepts.
        let res = if token.len() == TOKEN_LEN {
            // Not `sign_prehash`: it passes `rsa` no RNG, leaving the
            // exponentiation unmasked over a peer-chosen input.
            self.key
                .sign_with_rng(&mut self.blinding, self.padding.clone(), token)
                .map_err(KeyError::Rsa)
        } else {
            Err(KeyError::InvalidToken(token.len()))
        };
        core::future::ready(res)
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_wire
    }
}

/// Errors from key encoding, conversion and signing.
#[derive(Debug)]
pub enum KeyError {
    /// The key name contains a NUL, CR or LF, which would corrupt the
    /// public-key line or the AUTH payload carrying it.
    InvalidName,
    /// The key name is so long that the public-key line would not fit
    /// the AUTH packet that carries it. Carries the length offered.
    NameTooLong(usize),
    /// The modulus is not 2048 bits, which the fixed-size ADB
    /// public-key struct cannot express. Carries the actual size.
    UnsupportedModulus(usize),
    /// The modulus is even, so it is not an RSA modulus at all and the
    /// Montgomery constant the format carries does not exist for it.
    EvenModulus,
    /// The public exponent is not an odd integer of at least 3 that
    /// fits the struct's 32-bit field.
    UnsupportedExponent,
    /// The AUTH token is not a 20-byte SHA-1 prehash. Carries its size.
    InvalidToken(usize),
    /// A key record's payload is longer than its 32-bit length field
    /// can describe. Carries the length that was offered.
    PayloadTooLarge(usize),
    /// PKCS#8 parsing or serialization failed.
    Pkcs8(rsa::pkcs8::Error),
    /// PKCS#1 parsing failed — the encoding older adb releases wrote.
    Pkcs1(rsa::pkcs1::Error),
    /// Key generation or signing failed.
    Rsa(rsa::Error),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("key name contains a NUL, CR or LF"),
            Self::NameTooLong(len) => f.write_fmt(format_args!(
                "key name of {len} bytes leaves the public key too large for one AUTH packet"
            )),
            Self::UnsupportedModulus(bits) => f.write_fmt(format_args!(
                "unsupported modulus size: {bits} bits, need 2048"
            )),
            Self::EvenModulus => f.write_str("modulus is even, so it is not an RSA modulus"),
            Self::UnsupportedExponent => {
                f.write_str("public exponent is not an odd 32-bit integer of at least 3")
            }
            Self::InvalidToken(len) => f.write_fmt(format_args!(
                "expected a 20-byte SHA-1 prehash token, got {len}"
            )),
            Self::PayloadTooLarge(len) => f.write_fmt(format_args!(
                "key record payload of {len} bytes exceeds the 32-bit length field"
            )),
            Self::Pkcs8(e) => f.write_fmt(format_args!("PKCS#8: {e}")),
            Self::Pkcs1(e) => f.write_fmt(format_args!("PKCS#1: {e}")),
            Self::Rsa(e) => f.write_fmt(format_args!("RSA: {e}")),
        }
    }
}

impl core::error::Error for KeyError {}
