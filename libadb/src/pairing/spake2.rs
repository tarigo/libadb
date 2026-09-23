//! SPAKE2 as BoringSSL does it, which is not as anyone else does it.
//!
//! This is not RFC 9382 and not the CFRG draft. It runs on
//! edwards25519, its transcript is its own, and it is what adbd speaks,
//! so it is what we speak. The crate `spake2` on crates.io implements a
//! different scheme and will not talk to a device.
//!
//! Two details carry the whole thing and are easy to get wrong.
//!
//! The mask points M and N lie *outside* the prime-order subgroup, on
//! purpose. So the scalars they are multiplied by must be used whole,
//! not reduced modulo the group order: reducing changes the answer.
//! Neither the password scalar nor the private scalar fits a reduced
//! scalar type for that reason, and both are handled here as plain
//! 256-bit numbers.
//!
//! The password is fed in already stretched, and the names carry their
//! trailing NUL. AOSP passes `sizeof("adb pair client")`, which is
//! sixteen bytes, not fifteen.

use alloc::vec::Vec;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rsa::rand_core::CryptoRngCore;
use rsa::sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// `SHA256("edwards25519 point generation seed (M)")`, which happens to
/// land on the curve at the first try and so is the point itself.
const M_BYTES: [u8; 32] = [
    0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13, 0x1c, 0x6b, 0x5c,
    0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf, 0x44, 0x1b, 0x88, 0xee, 0xd1, 0x2e,
];

/// `SHA256("edwards25519 point generation seed (N)")`, likewise.
const N_BYTES: [u8; 32] = [
    0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4, 0x46, 0x72, 0x10,
    0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32, 0x9a, 0x11, 0x69, 0x3b, 0xc7, 0x78,
];

/// The order of the prime-order subgroup, little-endian.
const ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Which side of the exchange this is. The host is always Alice.
///
/// Both are public because the algorithm is symmetric and anyone
/// standing in for a device — a test, an emulator — needs the other
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// Masks with M, and comes first in the transcript.
    Alice,
    /// Masks with N. Only a device is ever Bob.
    Bob,
}

/// Why the exchange could not go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Spake2Error {
    /// The peer's message was not 32 bytes.
    MessageLength(usize),
    /// The peer's message was 32 bytes that are not a curve point.
    NotAPoint,
}

impl core::fmt::Display for Spake2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MessageLength(n) => write!(f, "spake2 message is {n} bytes, not 32"),
            Self::NotAPoint => f.write_str("spake2 message does not decode to a curve point"),
        }
    }
}

impl core::error::Error for Spake2Error {}

/// Add two 256-bit little-endian numbers, discarding the carry.
/// Deliberately unreduced.
fn add_assign(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        a[i] = sum as u8;
        carry = sum >> 8;
    }
}

/// Double a 256-bit little-endian number in place.
fn double_assign(a: &mut [u8; 32]) {
    let copy = *a;
    add_assign(a, &copy);
}

/// Multiply a 256-bit little-endian number by eight.
///
/// BoringSSL's `left_shift_3`. The input is a reduced scalar, well
/// under 2^253, so nothing is lost off the top.
fn left_shift_3(n: &mut [u8; 32]) {
    let mut carry = 0u8;
    for byte in n.iter_mut() {
        let next = *byte >> 5;
        *byte = (*byte << 3) | carry;
        carry = next;
    }
}

/// Scalar multiplication by a whole 256-bit number, in constant time.
///
/// Not `Scalar`: that type reduces modulo the group order, and the
/// mask points have torsion, so reducing changes the answer.
fn mul_raw(point: &EdwardsPoint, scalar: &[u8; 32]) -> EdwardsPoint {
    let mut acc = EdwardsPoint::identity();
    for byte in scalar.iter().rev() {
        for bit in (0..8).rev() {
            acc = acc + acc;
            let sum = acc + point;
            let take = Choice::from((byte >> bit) & 1);
            acc = EdwardsPoint::conditional_select(&acc, &sum, take);
        }
    }
    acc
}

/// Reduce 64 bytes to a scalar and hand back its 32 little-endian bytes.
fn reduce_wide(wide: &[u8; 64]) -> [u8; 32] {
    Scalar::from_bytes_mod_order_wide(wide).to_bytes()
}

/// Prefix `data` with its length as eight little-endian bytes, the way
/// BoringSSL builds its transcript.
fn absorb(hash: &mut Sha512, data: &[u8]) {
    hash.update((data.len() as u64).to_le_bytes());
    hash.update(data);
}

/// One side of a SPAKE2 exchange.
pub struct Spake2 {
    role: Role,
    my_name: Vec<u8>,
    their_name: Vec<u8>,
    /// The ephemeral scalar, a multiple of eight and left unreduced.
    private_key: Zeroizing<[u8; 32]>,
    /// The full SHA-512 of the password, which the transcript absorbs.
    password_hash: Zeroizing<[u8; 64]>,
    /// The password scalar after the cofactor fix, also unreduced.
    password_scalar: Zeroizing<[u8; 32]>,
    my_msg: [u8; 32],
}

impl Spake2 {
    /// Start an exchange and produce this side's message.
    ///
    /// `password` goes in whole: for pairing it is the six-digit code
    /// with the TLS exporter's output appended, not the code alone.
    pub fn new<R: CryptoRngCore>(
        role: Role,
        my_name: &[u8],
        their_name: &[u8],
        password: &[u8],
        rng: &mut R,
    ) -> Self {
        let mut wide = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(wide.as_mut());
        let mut private_key = Zeroizing::new(reduce_wide(&wide));
        // Clearing the cofactor on our own scalar is what lets the
        // small-order points in the peer's mask cancel later.
        left_shift_3(&mut private_key);

        let password_hash = Zeroizing::new(Sha512::digest(password).into());
        let password_scalar = Zeroizing::new(Self::password_scalar(&password_hash));

        let mask = match role {
            Role::Alice => Self::point(&M_BYTES),
            Role::Bob => Self::point(&N_BYTES),
        };
        let base = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(*private_key));
        let my_msg = (base + mul_raw(&mask, &password_scalar))
            .compress()
            .to_bytes();

        Self {
            role,
            my_name: my_name.into(),
            their_name: their_name.into(),
            private_key,
            password_hash,
            password_scalar,
            my_msg,
        }
    }

    /// This side's 32-byte message, to send as a `SPAKE2_MSG` packet.
    pub fn message(&self) -> &[u8; 32] {
        &self.my_msg
    }

    /// Take the peer's message and derive the 64 bytes both sides now
    /// share, if the passwords matched.
    ///
    /// Nothing here says whether they did. That only shows when the
    /// first encrypted message fails to authenticate.
    ///
    /// The exchange is used up, whatever the outcome: its scalar is
    /// for one peer only, and everything secret it holds is zeroed on
    /// the way out. Take [`message`](Self::message) first if it is
    /// still needed. The result zeroes itself when dropped.
    pub fn finish(self, their_msg: &[u8]) -> Result<Zeroizing<[u8; 64]>, Spake2Error> {
        let their_msg: [u8; 32] = their_msg
            .try_into()
            .map_err(|_| Spake2Error::MessageLength(their_msg.len()))?;

        let masked = CompressedEdwardsY(their_msg)
            .decompress()
            .ok_or(Spake2Error::NotAPoint)?;

        // No subgroup check, as in BoringSSL: our cofactor-cleared scalar
        // kills the torsion anyway.
        let peer_mask = match self.role {
            Role::Alice => Self::point(&N_BYTES),
            Role::Bob => Self::point(&M_BYTES),
        };
        let unmasked = masked - mul_raw(&peer_mask, &self.password_scalar);
        let shared = mul_raw(&unmasked, &self.private_key).compress().to_bytes();

        let (alice_name, bob_name, alice_msg, bob_msg) = match self.role {
            Role::Alice => (&self.my_name, &self.their_name, &self.my_msg, &their_msg),
            Role::Bob => (&self.their_name, &self.my_name, &their_msg, &self.my_msg),
        };

        // Always in Alice's order, whichever side is building it.
        let mut hash = Sha512::new();
        absorb(&mut hash, alice_name);
        absorb(&mut hash, bob_name);
        absorb(&mut hash, alice_msg);
        absorb(&mut hash, bob_msg);
        absorb(&mut hash, &shared);
        absorb(&mut hash, self.password_hash.as_ref());
        Ok(Zeroizing::new(hash.finalize().into()))
    }

    /// The password scalar, with BoringSSL's cofactor fix.
    ///
    /// The mask points have torsion, so a scalar that is not a multiple
    /// of eight leaks three bits of the password. BoringSSL adds `l`,
    /// `2l`, `4l` in turn, each test on the running value, never
    /// reducing, until the low three bits are zero.
    fn password_scalar(password_hash: &[u8; 64]) -> [u8; 32] {
        let mut scalar = reduce_wide(password_hash);
        let mut order = ORDER;
        for bit in 0..3u32 {
            let mask = 1u8 << bit;
            let set = (scalar[0] & mask).ct_eq(&mask);
            let mut addend = [0u8; 32];
            for (dst, src) in addend.iter_mut().zip(order.iter()) {
                *dst = u8::conditional_select(&0, src, set);
            }
            add_assign(&mut scalar, &addend);
            double_assign(&mut order);
        }
        debug_assert_eq!(scalar[0] & 7, 0);
        scalar
    }

    /// One of the two fixed mask points.
    fn point(bytes: &[u8; 32]) -> EdwardsPoint {
        CompressedEdwardsY(*bytes)
            .decompress()
            .expect("M and N are curve points, checked by a test")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::vec;
    use rsa::rand_core::{CryptoRng, RngCore};
    use rsa::sha2::Sha256;

    const CLIENT: &[u8] = b"adb pair client\0";
    const SERVER: &[u8] = b"adb pair server\0";

    /// Hands out one fixed block, so a vector can pin the scalars.
    struct FixedRng(vec::Vec<u8>);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!("only fill_bytes is used")
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!("only fill_bytes is used")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0[..dest.len()]);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    fn seed(from: u8) -> FixedRng {
        FixedRng((0..64u8).map(|i| from.wrapping_add(i)).collect())
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }

    #[test]
    fn the_mask_points_are_the_hashes_of_their_seeds() {
        // BoringSSL derives M and N by hashing a seed string until the
        // result lands on the curve, and for both it lands on the first
        // try. So the constants are checkable without any curve
        // arithmetic at all, which is worth doing: the same seeds under
        // the RFC 9382 procedure give different points that a device
        // will not accept.
        let m: [u8; 32] = Sha256::digest(b"edwards25519 point generation seed (M)").into();
        let n: [u8; 32] = Sha256::digest(b"edwards25519 point generation seed (N)").into();

        assert_eq!(m, M_BYTES);
        assert_eq!(n, N_BYTES);
    }

    #[test]
    fn the_mask_points_sit_outside_the_prime_order_subgroup() {
        // This is why the scalars must not be reduced: multiplying a
        // torsion point by `s` and by `s mod l` gives different
        // answers.
        for bytes in [M_BYTES, N_BYTES] {
            let point = Spake2::point(&bytes);
            assert_ne!(
                mul_raw(&point, &ORDER),
                EdwardsPoint::identity(),
                "a point of prime order would make the cofactor fix pointless"
            );
        }
    }

    #[test]
    fn the_cofactor_fix_clears_three_bits_without_reducing() {
        let hash: [u8; 64] = Sha512::digest(b"592781").into();

        let scalar = Spake2::password_scalar(&hash);

        assert_eq!(scalar[0] & 7, 0, "the low three bits are cleared");
        assert_ne!(
            scalar,
            reduce_wide(&hash),
            "and the value is no longer the reduced hash"
        );
    }

    #[test]
    fn multiplying_by_eight_matches_the_shift_it_is_named_after() {
        let mut n = [0u8; 32];
        n[0] = 0xFF;
        n[1] = 0x01;

        left_shift_3(&mut n);

        // 0x01FF * 8 = 0x0FF8
        assert_eq!(n[0], 0xF8);
        assert_eq!(n[1], 0x0F);
        assert!(n[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_exchange_matches_an_independent_implementation() {
        // Fixed scalars and a fixed password, against values produced
        // by a separate implementation written from the same BoringSSL
        // source. Every constant this pins — the mask points, the
        // cofactor fix, the length-prefixed transcript, the NUL inside
        // each name — is one whose absence looks exactly like a wrong
        // pairing code on the wire.
        let alice = Spake2::new(Role::Alice, CLIENT, SERVER, b"592781", &mut seed(0));
        let bob = Spake2::new(Role::Bob, SERVER, CLIENT, b"592781", &mut seed(64));

        assert_eq!(
            hex(alice.message()),
            "d75922a7455e51fee339250f9b4dcceb4426ef7bb77f24b310ee646e7d9dbf8b"
        );
        assert_eq!(
            hex(bob.message()),
            "c1e770dd362fa9def9dc0d18ac3155345f4f5905362ed252ad5b9828d23484ef"
        );
        assert_eq!(
            hex(alice.password_scalar.as_ref()),
            "509a79489dd16b364e842cfce8062a604e3e67ebf2f4aaf828b4f299d7a6605c"
        );
        assert_eq!(
            hex(alice.private_key.as_ref()),
            "d0e31113846fb901851ab16da0423167ce0aa31e960899d4d306afa52387962b"
        );

        let key = alice.finish(bob.message()).unwrap();
        assert_eq!(
            hex(key.as_ref()),
            "517fa9aa29d0d1a5b39490907434cb9d8024c2335d8a30970e04332f8d972da7\
             e9b62a285021dd5e52bbb8d32fa42ff2887f43416b32db4a0cf9eee5db3a665d"
        );
    }

    #[test]
    fn both_sides_reach_the_same_key_when_the_codes_match() {
        let alice = Spake2::new(Role::Alice, CLIENT, SERVER, b"314159", &mut seed(7));
        let bob = Spake2::new(Role::Bob, SERVER, CLIENT, b"314159", &mut seed(200));
        let (to_bob, to_alice) = (*alice.message(), *bob.message());

        let from_alice = alice.finish(&to_alice).unwrap();
        let from_bob = bob.finish(&to_bob).unwrap();

        assert_eq!(from_alice, from_bob);
    }

    #[test]
    fn a_wrong_code_parts_the_two_sides_without_saying_so() {
        // SPAKE2 itself never reports a mismatch. The keys simply
        // differ, and only the first encrypted message notices.
        let alice = Spake2::new(Role::Alice, CLIENT, SERVER, b"314159", &mut seed(7));
        let bob = Spake2::new(Role::Bob, SERVER, CLIENT, b"271828", &mut seed(200));
        let (to_bob, to_alice) = (*alice.message(), *bob.message());

        let from_alice = alice.finish(&to_alice).unwrap();
        let from_bob = bob.finish(&to_bob).unwrap();

        assert_ne!(from_alice, from_bob);
    }

    #[test]
    fn a_message_of_the_wrong_shape_is_refused() {
        let alice = || Spake2::new(Role::Alice, CLIENT, SERVER, b"592781", &mut seed(0));

        assert_eq!(
            alice().finish(&[0u8; 31]),
            Err(Spake2Error::MessageLength(31))
        );
        // y = 2 satisfies no point on the curve.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert_eq!(alice().finish(&not_a_point), Err(Spake2Error::NotAPoint));
    }
}
