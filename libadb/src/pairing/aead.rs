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

/// The cipher for one pairing session. Each direction counts its
/// own nonces from zero, as the peer does.
///
/// Dropping it wipes the AES key schedule, but not the GHASH subkey.
/// `polyval`, which holds that, clears it only with a feature of its
/// own, and on x86 not even then: there its state sits behind
/// `ManuallyDrop` so that the backend can be picked at run time.
pub(crate) struct Cipher {
    key: Aes128Gcm,
    encrypt_counter: u64,
    decrypt_counter: u64,
}

impl Cipher {
    /// Stretch the 64 bytes SPAKE2 agreed on into a session key. No
    /// salt, as in AOSP.
    pub(crate) fn new(key_material: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, key_material);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(HKDF_INFO, key.as_mut())
            .expect("HKDF-SHA256 stretches to 8160 bytes, and the key is 16");
        Self {
            // By reference: `into()` would leave an unwiped copy behind.
            key: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key.as_ref())),
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }

    /// The nonce for message number `counter`: the counter itself,
    /// little-endian, in the first eight of twelve bytes.
    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt one message, spending a nonce.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
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
            .expect("GCM seals anything short of 64 GiB");
        self.encrypt_counter += 1;
        sealed
    }

    /// Decrypt one message; `None` if it does not authenticate. Only a
    /// message that opens spends a nonce. With pairing a failure means
    /// one thing: the codes did not match, so the two sides hold
    /// different keys.
    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
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
            .ok()?;
        self.decrypt_counter += 1;
        Some(opened)
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
        (Cipher::new(&material), Cipher::new(&material))
    }

    #[test]
    fn what_one_side_seals_the_other_opens() {
        let (mut host, mut device) = pair();

        let sealed = host.seal(b"peer info");

        assert_eq!(device.open(&sealed).unwrap(), b"peer info");
    }

    #[test]
    fn sealing_adds_exactly_a_tag() {
        let (mut host, _) = pair();

        let sealed = host.seal(&[0u8; 8192]);

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
        let _ = device.seal(b"device spoke first");

        let sealed = host.seal(b"host message");

        assert_eq!(device.open(&sealed).unwrap(), b"host message");
    }

    #[test]
    fn a_different_password_cannot_open_the_message() {
        // This is the only signal a wrong pairing code produces: the
        // key material differs, so the tag fails.
        let mut host = Cipher::new(&[0x5Au8; 64]);
        let mut device = Cipher::new(&[0xA5u8; 64]);

        let sealed = host.seal(b"peer info");

        assert_eq!(device.open(&sealed), None);
    }

    #[test]
    fn the_first_message_is_byte_for_byte_what_another_library_produces() {
        // Pins what a peer has to agree with us about for the first
        // message: the HKDF info string, the zero salt, and a nonce of
        // twelve zero bytes. Where the counter sits in later nonces is
        // pinned above. Node's `crypto` (`hkdfSync` and `aes-128-gcm`, on
        // OpenSSL 3.6) gives the same bytes from the same inputs.
        let mut cipher = Cipher::new(&[0x5Au8; 64]);

        let sealed = cipher.seal(b"adb pairing probe");

        let expected = [
            0x0e, 0xd1, 0x25, 0xb7, 0x0e, 0x3a, 0xf6, 0x4b, 0x27, 0xa9, 0x74, 0xb9, 0xfa, 0xc0,
            0x38, 0xa7, 0x82, 0xbe, 0xdf, 0xcb, 0x57, 0x6d, 0x15, 0x4d, 0x92, 0x59, 0x77, 0x37,
            0x0f, 0x1a, 0x41, 0x8e, 0x54,
        ];
        assert_eq!(sealed, expected);
    }
}
