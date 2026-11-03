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
    // Fixed scalars and a fixed password, against the values a Python
    // transcription of BoringSSL's spake25519.cc computes with plain
    // integers and hashlib, sharing nothing with the arithmetic here.
    // Every constant this pins — the mask points, the cofactor fix,
    // the length-prefixed transcript, the trailing NUL on each name —
    // is one whose absence looks exactly like a wrong pairing code on
    // the wire.
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
fn a_message_that_is_not_a_point_is_refused() {
    let alice = || Spake2::new(Role::Alice, CLIENT, SERVER, b"592781", &mut seed(0));

    // y = 2 satisfies no point on the curve.
    let mut not_a_point = [0u8; 32];
    not_a_point[0] = 2;
    assert_eq!(alice().finish(&not_a_point), Err(Spake2Error::NotAPoint));
}
