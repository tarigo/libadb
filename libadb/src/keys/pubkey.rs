//! Encoder for the ADB (mincrypt `RSAPublicKey`) public-key format.

use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

use crate::base::protocol::command::MAX_PAYLOAD;

use super::KeyError;

/// Modulus size the format is fixed at: RSA-2048, in bytes.
const MODULUS_SIZE: usize = 256;
/// The same modulus counted in the 32-bit words adbd expects.
const MODULUS_WORDS: u32 = (MODULUS_SIZE / 4) as u32;
/// `len | n0inv | n | rr | exponent`.
const ENCODED_SIZE: usize = 4 + 4 + MODULUS_SIZE + MODULUS_SIZE + 4;
/// What the line spends before the name: the base64 blob and the space
/// that follows it.
const PREFIX_LEN: usize = ENCODED_SIZE.div_ceil(3) * 4 + 1;

/// Encode a public key as the `adbkey.pub` line: base64 of the
/// mincrypt struct, then `" <name>"` when `name` is non-empty.
///
/// No trailing NUL and no newline — the AUTH payload appends the NUL
/// (see [`AdbKey::public_key_wire`]), key files append their own
/// newline, if any.
///
/// The key is checked as far as the format demands: 2048 bits, an odd
/// modulus, and an odd exponent of at least 3 that fits the struct's
/// 32-bit field. `RsaPublicKey::new` rejects what is not a usable RSA
/// key at all — an even modulus, an exponent below 3 or even — but it
/// admits any modulus size and exponents up to 2^33, so the two limits
/// this format fixes are checked here whichever constructor built the
/// key. Encoding a degenerate one would hand the device something it
/// can only reject, or, for `e = 1`, something anyone can forge
/// signatures against.
///
/// `name` is bounded too: the blob travels in a single AUTH packet.
///
/// [`AdbKey::public_key_wire`]: super::AdbKey::public_key_wire
pub fn encode_public_key(key: &RsaPublicKey, name: &str) -> Result<Vec<u8>, KeyError> {
    validate_name(name)?;

    let blob = mincrypt_struct(key)?;
    let mut out = Base64::encode_string(&blob).into_bytes();
    if !name.is_empty() {
        out.push(b' ');
        out.extend_from_slice(name.as_bytes());
    }
    Ok(out)
}

/// Reject a name the format cannot carry: the blob is a single line,
/// terminated by a NUL on the wire, and it has to fit one AUTH packet.
pub(super) fn validate_name(name: &str) -> Result<(), KeyError> {
    if name.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')) {
        return Err(KeyError::InvalidName);
    }
    // A name past this point would only fail at first connect, on the
    // one exchange that carries the public key.
    if name.len() > MAX_PAYLOAD as usize - PREFIX_LEN - 1 {
        return Err(KeyError::NameTooLong(name.len()));
    }
    Ok(())
}

/// Build the 524-byte struct adbd reads: word count, Montgomery
/// `n0inv`, little-endian modulus, `R^2 mod n`, and the exponent.
fn mincrypt_struct(key: &RsaPublicKey) -> Result<[u8; ENCODED_SIZE], KeyError> {
    let n = key.n();
    let bits = n.bits();
    if bits != MODULUS_SIZE * 8 {
        return Err(KeyError::UnsupportedModulus(bits));
    }

    // 64 little-endian words and 256 little-endian bytes are the same
    // bytes, so the limbs need no extraction of their own.
    let mut n_le = n.to_bytes_le();
    n_le.resize(MODULUS_SIZE, 0);

    let n0 = u32::from_le_bytes(n_le[..4].try_into().unwrap());
    // The lifting below converges only for an odd modulus.
    if n0 % 2 == 0 {
        return Err(KeyError::EvenModulus);
    }
    let n0inv = neg_inverse_mod_2_32(n0);

    // R = 2^2048, so rr = R^2 mod n — and can be shorter than n.
    let mut rr_le = ((BigUint::from(1u32) << (MODULUS_SIZE * 16)) % n).to_bytes_le();
    rr_le.resize(MODULUS_SIZE, 0);

    let e_le = key.e().to_bytes_le();
    if e_le.len() > 4 {
        return Err(KeyError::UnsupportedExponent);
    }
    let mut e_bytes = [0u8; 4];
    e_bytes[..e_le.len()].copy_from_slice(&e_le);
    // `e = 1` would let anyone forge; an even or zero one is no
    // exponent at all.
    let e = u32::from_le_bytes(e_bytes);
    if e < 3 || e % 2 == 0 {
        return Err(KeyError::UnsupportedExponent);
    }

    let mut out = [0u8; ENCODED_SIZE];
    out[0..4].copy_from_slice(&MODULUS_WORDS.to_le_bytes());
    out[4..8].copy_from_slice(&n0inv.to_le_bytes());
    out[8..8 + MODULUS_SIZE].copy_from_slice(&n_le);
    out[8 + MODULUS_SIZE..8 + 2 * MODULUS_SIZE].copy_from_slice(&rr_le);
    out[8 + 2 * MODULUS_SIZE..].copy_from_slice(&e_bytes);
    Ok(out)
}

/// `-(n0^-1) mod 2^32` for an odd `n0`, by Hensel lifting: `inv = n0`
/// is already correct modulo 8, and each step doubles the correct bits
/// (3 → 6 → 12 → 24 → 48), so four steps cover the full word.
fn neg_inverse_mod_2_32(n0: u32) -> u32 {
    let mut inv = n0;
    for _ in 0..4 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}
