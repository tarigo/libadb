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

/// Throwaway RSA-2048 key for these tests only.
const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfJ471H4SpiWaP
1nN1KkLbV227dSZZu0V+AkFMRVHBQ/eu82tfbG9aLSFtDWjP58h2IvjtPtnHupd2
hyTgHiMt1Pa9gjxhjzdIYiZbNv3sArBhD/L0xgZE7WEwdwB9FE4EaFXQwola81oI
H+lqXEVWcQtebpP8Sam9HrGhpwtvuKRUfeANRUFmEuPEnLrds+OsalvPT893IcGO
N/rmb9BK4343jKvPtGcnVtkftDAOFudwENPGZjlC47WkR4/q1pq4fD327YEL0DHc
Hw42K0g3GBuNzyQTZVtnbK30ogIQFF7ug+A/PAgXu8KLrAoNgHH9W3aeXSNYrXo6
5uFYbsmHAgMBAAECggEAPTuMim2mbk3xWkzRXhY048v26YUQjLx655i5g701z6w1
Oqfnuy5uhxzO+/SJS1grbZxV9n1Ub74v8Qfc3adqtIL3rYDSd1yREfXFORnmxutf
7fAjcx5PIizMVEestfLec16rCacXDpmLHY4dkXDPsorKq3nS0OGMfzk0cXPh+AjQ
Nz0kXljEP9Hb1dby2Zgh+mAFKD9RU5TeiNkxIsVaR9Fhl7d2cNZhy8gkoOqUhOit
mAmCvIb1FOAUiPr4iqEjWJOciVPIIHY5NYwy4ktHwsyPH8o3VFggxgc0HNDqywdg
sXKZpTvtmvXNGIJ7tkXzOCqknWixEHNTKK3Jq5s2vQKBgQDQPtg4HXEoRo7wlAjm
nMPWZQo1m9o91RSYmyV1x8FVjeFpuNWy5UpnToNPbuVuyiEtxVOrtG/AQGDF6/pI
Y87i8/VqlZ/gWqM+u/gwdijVvNHzndxSTdg+Ea2G/9gvWlqkDz0NVcgw49WyLq/s
LXbwELoRvGp5PuVpuG4lo92b7QKBgQDDps3r2DOMrrIIR8Yf5bbUV2GyfF9ahi9Q
JxVShfeN6Qogi6OIdERGZdHx29LEF9lAX4+On8VyyF/YBw19E+4bgJ1K+1MLc8rx
ME+ixaCk0zMvpRZ68EE0kCv1kTlJE+6zThJ4NSwH6EK39sUTXULfFLsNedJkzkkm
+6gzEuyUwwKBgQDITtruRyu0YQJXWR2ircIWdMQ4QrzPYynXjMygmU9Xew0LA5bS
6IkEC9p0yqf4RIdbnoZYEEy58XLkjpMFlLPJTH6RUnEhfi2uR2J5Qv8OcPzGx97I
cEaDlb+Dro8FJXUwf9PrAst4c373UL85f5X7XyuLqeAE1kIXyiZxIEknFQKBgHOY
nTfIMIThPnzX8z4rWf9RdX6gLzJr745a2SU908q7smkSN9fKYgB57jYI3BlRweFf
1JC+40jzDHW1jQmmedsz/TstDJ7KllA0bAjO3SAlTKvMzWBrjQsCV4aqe/8qULEN
4qm1OMOfPbQ1j7DmPDlTpUTMAjvfCaeHrpQmjTNDAoGAP1mczr6EOxWe+sU2pI8n
sK+8KgzS3RWlDluOLzXjC1cNOLQeihXWGfqr028FpQ5XURnOkg/C3XrnAXekLmwz
PzYB4KuqFNwbz5ZRFESRkGzidJ3HFCwWE6XCvx0djkTZX3GSv+bDf5nrc3S0uyoQ
HXG1VnHeCDbKytxtqaBZLX0=
-----END PRIVATE KEY-----
";

const TEST_NAME: &str = "unit@test";

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
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut rng, TEST_NAME).unwrap();
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
