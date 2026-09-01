#![cfg(all(feature = "keys", any(feature = "tokio", feature = "smol")))]

//! End-to-end check that a real key drives the first-connect handshake.
//!
//! The device side does what adbd does with an unknown key: reject the
//! signature, ask again, and take the public key. The test then decodes
//! that key blob off the wire — rather than trusting the encoder —
//! checks every field of the mincrypt struct against the arithmetic it
//! claims, and verifies the earlier signature with the key it rebuilt.
//! Encoder and signer have to agree for that to pass, so a formatting
//! mistake cannot hide behind its own encoder.

use base64ct::{Base64, Encoding};
use libadb::keys::AdbKey;
use libadb::protocol::command::{AUTH_RSAPUBLICKEY, AUTH_SIGNATURE};
use libadb::Connection;
use rand_chacha::ChaCha8Rng;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::rand_core::SeedableRng;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::{BigUint, RsaPublicKey};
use sha1::Sha1;

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{wrap, AuthPolicy, FakeDevice, DEFAULT_BANNER};

#[path = "common/common.rs"]
mod common;

#[path = "test_key/test_key.rs"]
mod test_key;
use test_key::{NAME, PKCS8_PEM};

/// Rebuild the public key from an `AUTH(RSAPUBLICKEY)` payload the way
/// adbd does, checking every field of the struct on the way: a device
/// that cannot reduce with `n0inv` and `rr` rejects the key, and a
/// signature check alone would never notice.
fn public_key_from_wire(payload: &[u8]) -> RsaPublicKey {
    let line = payload.strip_suffix(b"\0").expect("adbd expects a NUL");
    let space = line.iter().position(|&b| b == b' ').unwrap();
    let blob = Base64::decode_vec(core::str::from_utf8(&line[..space]).unwrap()).unwrap();

    assert_eq!(blob.len(), 524, "mincrypt struct size");
    assert_eq!(
        u32::from_le_bytes(blob[0..4].try_into().unwrap()),
        64,
        "word count"
    );

    let n = BigUint::from_bytes_le(&blob[8..264]);
    let n0inv = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    let n0 = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    assert_eq!(
        n0inv.wrapping_mul(n0),
        u32::MAX,
        "n0inv must invert the modulus' low word"
    );
    assert_eq!(
        BigUint::from_bytes_le(&blob[264..520]),
        (BigUint::from(1u32) << 4096usize) % &n,
        "rr must be R^2 mod n"
    );

    let e = BigUint::from(u32::from_le_bytes(blob[520..524].try_into().unwrap()));
    RsaPublicKey::new(n, e).expect("the blob must describe a usable key")
}

// ---------------------------------------------------------------------------
// Tests: first connect with a real key
// ---------------------------------------------------------------------------

rt_test! {
async fn a_real_key_completes_the_pubkey_handshake_with_a_verifiable_signature() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let key = AdbKey::from_pkcs8_pem(PKCS8_PEM, &mut rng, NAME).unwrap();
    // adbd issues 20-byte SHA-1 prehashes; a real signer insists on it.
    let first_token = [0x11u8; 20];
    let dev = FakeDevice::new().auth(AuthPolicy::RequirePublicKey {
        first_token: first_token.to_vec(),
        second_token: [0x22u8; 20].to_vec(),
        expected_pubkey: key.public_key_wire().to_vec(),
    });

    let (handle, addr) = dev.bind().await;
    let device = rt::spawn(async move { handle.accept().await });
    let stream = rt::connect(addr).await;
    let conn = Connection::<_>::connect_with_raw_banner(wrap(stream), key, b"host::")
        .await
        .unwrap();

    assert_eq!(conn.device_banner(), Some(DEFAULT_BANNER));

    let session = rt::join(device).await;
    let auth = session.auth_payloads();
    assert_eq!(auth.len(), 2, "one signature, then the public key");
    assert_eq!(auth[0].0, AUTH_SIGNATURE);
    assert_eq!(auth[1].0, AUTH_RSAPUBLICKEY);

    VerifyingKey::<Sha1>::new(public_key_from_wire(&auth[1].1))
        .verify_prehash(
            &first_token,
            &Signature::try_from(auth[0].1.as_slice()).unwrap(),
        )
        .expect("the key sent on the wire must verify the signature sent before it");
}
}
