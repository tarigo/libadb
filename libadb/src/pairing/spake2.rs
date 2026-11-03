//! SPAKE2 as BoringSSL does it, which is not as anyone else does it.
//!
//! This is not RFC 9382 and not the CFRG draft. It runs on
//! edwards25519, its transcript is its own, and it is what adbd speaks,
//! so it is what we speak. The crate `spake2` on crates.io implements a
//! different scheme and will not talk to a device.
//!
//! Two details carry the whole thing and are easy to get wrong.
//!
//! The mask points M and N lie *outside* the prime-order subgroup:
//! BoringSSL took them straight from a hash without clearing the
//! cofactor, and adbd uses them as they are. So the scalars they are
//! multiplied by must be used whole, not reduced modulo the group
//! order: reducing changes the answer.
//! Neither the password scalar nor the private scalar fits a reduced
//! scalar type for that reason, and both are handled here as plain
//! 256-bit numbers.
//!
//! The password is not the pairing code alone: pairing appends the TLS
//! exporter's output to it. And the names carry their trailing NUL.
//! AOSP passes `sizeof("adb pair client")`, which is sixteen bytes, not
//! fifteen.

#[cfg(test)]
mod tests;

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
    /// The peer's message was not 32 bytes. [`pair`](crate::pairing::pair)
    /// reports a SPAKE2 packet of any other size this way;
    /// [`Spake2::finish`] takes exactly 32.
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

/// One side of SPAKE2 as BoringSSL runs it on edwards25519, which is
/// what adbd speaks: not RFC 9382, and not what the `spake2` crate
/// implements. [`pair`](crate::pairing::pair) runs one as
/// [`Role::Alice`]; it is public so that whatever stands in for a
/// device, a test or an emulator, can run the other side.
///
/// The scalars it holds, and the bytes of the point both sides arrive
/// at, are wiped as they go. Two kinds of copy are not. SHA-512's
/// working state: `sha2` 0.10 has no way to clear it, so the hashers
/// that take in the password and the transcript leave their last state
/// in memory they free, and the transcript's is as good as the key it
/// finishes into. And the temporaries the scalar and curve arithmetic
/// leave on the stack along the way. The key is used once, for one
/// `PeerInfo` each way.
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
    /// `password` goes in whole: for pairing it is the pairing code
    /// with the TLS exporter's output appended, not the code alone.
    ///
    /// The names go in whole too, NUL and all: adbd's are
    /// `b"adb pair client\0"` for the host (Alice) and
    /// `b"adb pair server\0"` for the device (Bob), each side passing
    /// its own first.
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
        // Reducing is harmless here, unlike against the masks: the base
        // point has prime order, so the product comes out the same.
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
    pub fn finish(self, their_msg: &[u8; 32]) -> Result<Zeroizing<[u8; 64]>, Spake2Error> {
        let masked = CompressedEdwardsY(*their_msg)
            .decompress()
            .ok_or(Spake2Error::NotAPoint)?;

        // No subgroup check, as in BoringSSL: our cofactor-cleared scalar
        // kills the torsion anyway.
        let peer_mask = match self.role {
            Role::Alice => Self::point(&N_BYTES),
            Role::Bob => Self::point(&M_BYTES),
        };
        let unmasked = masked - mul_raw(&peer_mask, &self.password_scalar);
        let shared = Zeroizing::new(mul_raw(&unmasked, &self.private_key).compress().to_bytes());

        let (alice_name, bob_name, alice_msg, bob_msg) = match self.role {
            Role::Alice => (&self.my_name, &self.their_name, &self.my_msg, their_msg),
            Role::Bob => (&self.their_name, &self.my_name, their_msg, &self.my_msg),
        };

        // Always in Alice's order, whichever side is building it.
        let mut hash = Sha512::new();
        absorb(&mut hash, alice_name);
        absorb(&mut hash, bob_name);
        absorb(&mut hash, alice_msg);
        absorb(&mut hash, bob_msg);
        absorb(&mut hash, shared.as_ref());
        absorb(&mut hash, self.password_hash.as_ref());
        Ok(Zeroizing::new(hash.finalize().into()))
    }

    /// The password scalar, with BoringSSL's cofactor fix.
    ///
    /// The mask points have torsion, so a scalar that is not a multiple
    /// of eight leaks up to three bits of the password. BoringSSL
    /// reduces the hash, then clears the low three bits in turn, adding
    /// `l`, `2l` and `4l` whenever the running value has that bit set,
    /// and does not reduce again.
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
