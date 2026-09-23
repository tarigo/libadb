//! The cipher that protects the `PeerInfo` exchange.
//!
//! AES-128-GCM with a key stretched out of the SPAKE2 secret, and a
//! nonce that is nothing but a counter. AOSP keeps it in
//! `pairing_auth/aes_128_gcm.cpp`.

use alloc::vec::Vec;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use hkdf::Hkdf;
use rsa::sha2::Sha256;
use zeroize::Zeroizing;

/// The HKDF info string, without a trailing NUL — AOSP passes
/// `sizeof(info) - 1`.
const HKDF_INFO: &[u8] = b"adb pairing_auth aes-128-gcm key";

/// AES-128, so sixteen bytes.
const KEY_LEN: usize = 16;

/// What GCM adds to a message.
pub(crate) const TAG_LEN: usize = 16;

/// Why a message could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadError {
    /// Stretching the SPAKE2 secret into a key failed. Only a length
    /// far outside what HKDF allows can do this.
    Kdf,
    /// The ciphertext did not authenticate. With pairing this means one
    /// thing: the codes did not match, so the two sides are holding
    /// different keys.
    Decrypt,
    /// Encryption failed, which for GCM means the message was absurdly
    /// long.
    Encrypt,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kdf => f.write_str("deriving the pairing key failed"),
            Self::Decrypt => {
                f.write_str("pairing message did not authenticate; the codes did not match")
            }
            Self::Encrypt => f.write_str("encrypting the pairing message failed"),
        }
    }
}

impl core::error::Error for AeadError {}

/// The cipher for one pairing session. Each direction counts its
/// own nonces from zero, as the peer does.
pub(crate) struct Cipher {
    key: Aes128Gcm,
    encrypt_counter: u64,
    decrypt_counter: u64,
}

impl Cipher {
    /// Stretch the 64 bytes SPAKE2 agreed on into a session key. No
    /// salt, as in AOSP.
    pub(crate) fn new(key_material: &[u8]) -> Result<Self, AeadError> {
        let hkdf = Hkdf::<Sha256>::new(None, key_material);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(HKDF_INFO, key.as_mut())
            .map_err(|_| AeadError::Kdf)?;
        Ok(Self {
            // By reference: `into()` would leave an unwiped copy behind.
            key: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key.as_ref())),
            encrypt_counter: 0,
            decrypt_counter: 0,
        })
    }

    /// The nonce for message number `counter`: the counter itself,
    /// little-endian, in the first eight of twelve bytes.
    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt one message, spending a nonce.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Self::nonce(self.encrypt_counter);
        let sealed = self
            .key
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| AeadError::Encrypt)?;
        self.encrypt_counter += 1;
        Ok(sealed)
    }

    /// Decrypt one message, spending a nonce.
    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Self::nonce(self.decrypt_counter);
        let opened = self
            .key
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| AeadError::Decrypt)?;
        self.decrypt_counter += 1;
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_schedule_wipes_itself_on_drop() {
        // `aes` clears its round keys only with its own `zeroize`
        // feature, and `aes-gcm` has no switch that turns it on. A
        // build without it still pairs, and leaves the key behind.
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<aes::Aes128>();
    }

    fn pair() -> (Cipher, Cipher) {
        let material = [0x5Au8; 64];
        (
            Cipher::new(&material).unwrap(),
            Cipher::new(&material).unwrap(),
        )
    }

    #[test]
    fn what_one_side_seals_the_other_opens() {
        let (mut host, mut device) = pair();

        let sealed = host.seal(b"peer info").unwrap();

        assert_eq!(device.open(&sealed).unwrap(), b"peer info");
    }

    #[test]
    fn sealing_adds_exactly_a_tag() {
        let (mut host, _) = pair();

        let sealed = host.seal(&[0u8; 8192]).unwrap();

        assert_eq!(sealed.len(), 8192 + TAG_LEN);
    }

    #[test]
    fn the_first_nonce_is_all_zeroes_and_the_next_counts_up() {
        assert_eq!(Cipher::nonce(0), [0u8; 12]);
        assert_eq!(
            Cipher::nonce(1),
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "the counter is little-endian in the first eight bytes"
        );
        assert_eq!(
            Cipher::nonce(0x0102_0304_0506_0708),
            [8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn the_two_directions_count_apart() {
        // Each side encrypts with its own counter and decrypts with the
        // peer's, so a sealed message must open at the same number it
        // was sealed at, whatever the other direction has done.
        let (mut host, mut device) = pair();
        let _ = device.seal(b"device spoke first").unwrap();

        let sealed = host.seal(b"host message").unwrap();

        assert_eq!(device.open(&sealed).unwrap(), b"host message");
    }

    #[test]
    fn a_different_password_cannot_open_the_message() {
        // This is the only signal a wrong pairing code produces: the
        // key material differs, so the tag fails.
        let mut host = Cipher::new(&[0x5Au8; 64]).unwrap();
        let mut device = Cipher::new(&[0xA5u8; 64]).unwrap();

        let sealed = host.seal(b"peer info").unwrap();

        assert_eq!(device.open(&sealed), Err(AeadError::Decrypt));
    }

    #[test]
    fn the_first_message_is_byte_for_byte_what_another_library_produces() {
        // Pins the three things a peer has to agree with us about: the
        // HKDF info string, the zero salt, and a nonce that is a
        // little-endian counter in a twelve-byte field. The expectation
        // came from an unrelated implementation of HKDF-SHA256 and
        // AES-128-GCM given the same inputs.
        let mut cipher = Cipher::new(&[0x5Au8; 64]).unwrap();

        let sealed = cipher.seal(b"adb pairing probe").unwrap();

        let expected = [
            0x0e, 0xd1, 0x25, 0xb7, 0x0e, 0x3a, 0xf6, 0x4b, 0x27, 0xa9, 0x74, 0xb9, 0xfa, 0xc0,
            0x38, 0xa7, 0x82, 0xbe, 0xdf, 0xcb, 0x57, 0x6d, 0x15, 0x4d, 0x92, 0x59, 0x77, 0x37,
            0x0f, 0x1a, 0x41, 0x8e, 0x54,
        ];
        assert_eq!(sealed, expected);
    }
}
