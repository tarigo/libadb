use super::*;

use alloc::format;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use rand_chacha::ChaCha8Rng;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::rand_core::{RngCore, SeedableRng};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;

use crate::auth::Authenticator;
use crate::base::mock::now;

/// Throwaway RSA-2048 key generated for these tests only. It guards no
/// real device and must never be reused anywhere else.
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

/// The `adbkey.pub` base64 token the reference `adb keygen` produced
/// for [`TEST_KEY_PEM`], cross-checked against an independent encoder.
/// It pins the wire format byte-for-byte and is name-independent.
const GOLDEN_PUB_B64: &str = "QAAAAMlTK9SHyW5Y4eY6eq1YI12edlv9cYANCqyLwrsXCDw/4IPuXhQQAqL0rWxnW2UTJM+NGxg3SCs2Dh/cMdALge32PXy4mtbqj0ekteNCOWbG0xBw5xYOMLQf2VYnZ7TPq4w3fuNK0G/m+jeOwSF3z0/PW2qs47PdupzE4xJmQUUN4H1UpLhvC6ehsR69qUn8k25eC3FWRVxq6R8IWvNaicLQVWgEThR9AHcwYe1EBsb08g9hsALs/TZbJmJIN49hPIK99tQtIx7gJId2l7rH2T7t+CJ2yOfPaA1tIS1ab2xfa/Ou90PBUUVMQQJ+RbtZJnW7bVfbQip1c9aPZomphB/1jiefyxQBBwt04IodWe8PDmq/hT8ptC2dNFZBlibQ1LaobD6ZheHGNXV55+Oh1Glr9KaYZqRdogBAdelWq3dcqUt4xtPS+Cd0ML290+xRG7wpG2M4rbtOuP4IkYE3OyigtzB2uDr+pr4naMfh8qILGJVQ8CLGn3uS2vtoI52aA3RUQDhfJCEWIdxRQDZQkCB+EYDfUHHGgP4X+UbQV6VoUdan+XHFuFRBSVS2jdeVIOnq2Tc4pXuQvxpr+vAf29WpJ18WvVP3VugdybbmC19tg9+BBcfMXtwot0pXGDhc/g9AZ4ODKCP7T3byv6A26cIlr6Q5eeX2Odacpo5ZQ2wE+ODoXAEAAQA=";

/// The same key as older adb releases wrote it.
const TEST_KEY_PKCS1_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnyeO9R+EqYlmj9ZzdSpC21dtu3UmWbtFfgJBTEVRwUP3rvNr
X2xvWi0hbQ1oz+fIdiL47T7Zx7qXdock4B4jLdT2vYI8YY83SGImWzb97AKwYQ/y
9MYGRO1hMHcAfRROBGhV0MKJWvNaCB/palxFVnELXm6T/EmpvR6xoacLb7ikVH3g
DUVBZhLjxJy63bPjrGpbz0/PdyHBjjf65m/QSuN+N4yrz7RnJ1bZH7QwDhbncBDT
xmY5QuO1pEeP6taauHw99u2BC9Ax3B8ONitINxgbjc8kE2VbZ2yt9KICEBRe7oPg
PzwIF7vCi6wKDYBx/Vt2nl0jWK16OubhWG7JhwIDAQABAoIBAD07jIptpm5N8VpM
0V4WNOPL9umFEIy8eueYuYO9Nc+sNTqn57subocczvv0iUtYK22cVfZ9VG++L/EH
3N2narSC962A0ndckRH1xTkZ5sbrX+3wI3MeTyIszFRHrLXy3nNeqwmnFw6Zix2O
HZFwz7KKyqt50tDhjH85NHFz4fgI0Dc9JF5YxD/R29XW8tmYIfpgBSg/UVOU3ojZ
MSLFWkfRYZe3dnDWYcvIJKDqlITorZgJgryG9RTgFIj6+IqhI1iTnIlTyCB2OTWM
MuJLR8LMjx/KN1RYIMYHNBzQ6ssHYLFymaU77Zr1zRiCe7ZF8zgqpJ1osRBzUyit
yaubNr0CgYEA0D7YOB1xKEaO8JQI5pzD1mUKNZvaPdUUmJsldcfBVY3habjVsuVK
Z06DT27lbsohLcVTq7RvwEBgxev6SGPO4vP1apWf4FqjPrv4MHYo1bzR853cUk3Y
PhGthv/YL1papA89DVXIMOPVsi6v7C128BC6EbxqeT7labhuJaPdm+0CgYEAw6bN
69gzjK6yCEfGH+W21FdhsnxfWoYvUCcVUoX3jekKIIujiHRERmXR8dvSxBfZQF+P
jp/Fcshf2AcNfRPuG4CdSvtTC3PK8TBPosWgpNMzL6UWevBBNJAr9ZE5SRPus04S
eDUsB+hCt/bFE11C3xS7DXnSZM5JJvuoMxLslMMCgYEAyE7a7kcrtGECV1kdoq3C
FnTEOEK8z2Mp14zMoJlPV3sNCwOW0uiJBAvadMqn+ESHW56GWBBMufFy5I6TBZSz
yUx+kVJxIX4trkdieUL/DnD8xsfeyHBGg5W/g66PBSV1MH/T6wLLeHN+91C/OX+V
+18ri6ngBNZCF8omcSBJJxUCgYBzmJ03yDCE4T581/M+K1n/UXV+oC8ya++OWtkl
PdPKu7JpEjfXymIAee42CNwZUcHhX9SQvuNI8wx1tY0JpnnbM/07LQyeypZQNGwI
zt0gJUyrzM1ga40LAleGqnv/KlCxDeKptTjDnz20NY+w5jw5U6VEzAI73wmnh66U
Jo0zQwKBgD9ZnM6+hDsVnvrFNqSPJ7CvvCoM0t0VpQ5bji814wtXDTi0HooV1hn6
q9NvBaUOV1EZzpIPwt165wF3pC5sMz82AeCrqhTcG8+WURREkZBs4nSdxxQsFhOl
wr8dHY5E2V9xkr/mw3+Z63N0tLsqEB1xtVZx3gg2ysrcbamgWS19
-----END RSA PRIVATE KEY-----
";

const TEST_NAME: &str = "unit@test";

/// Seeded stand-in for the CSPRNG a caller supplies; blinding needs
/// entropy but no test depends on which.
fn test_rng() -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(1)
}

fn test_public_key() -> RsaPublicKey {
    RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM)
        .expect("test fixture must parse")
        .to_public_key()
}

/// Encoder output, base64-decoded back to the raw 524-byte struct.
fn decoded_blob_of(key: &RsaPublicKey) -> Vec<u8> {
    let out = encode_public_key(key, "").unwrap();
    Base64::decode_vec(core::str::from_utf8(&out).unwrap()).unwrap()
}

/// The same, for the fixture key and its name.
fn decoded_blob() -> Vec<u8> {
    let out = encode_public_key(&test_public_key(), TEST_NAME).unwrap();
    let space = out
        .iter()
        .position(|&b| b == b' ')
        .expect("a space must separate base64 from the name");
    Base64::decode_vec(core::str::from_utf8(&out[..space]).unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// Tests: public-key encoding
// ---------------------------------------------------------------------------

#[test]
fn encode_output_is_base64_blob_then_space_then_name() {
    let out = encode_public_key(&test_public_key(), TEST_NAME).unwrap();
    let space = out
        .iter()
        .position(|&b| b == b' ')
        .expect("a space must separate base64 from the name");
    let (token, rest) = out.split_at(space);
    assert_eq!(
        token.len(),
        700,
        "524 struct bytes must encode to exactly 700 base64 chars"
    );
    assert!(Base64::decode_vec(core::str::from_utf8(token).unwrap()).is_ok());
    assert_eq!(rest, b" unit@test");
    assert!(
        !out.contains(&0) && !out.contains(&b'\n'),
        "the file form carries no NUL and no newline"
    );
}

#[test]
fn encoded_struct_is_524_bytes_and_advertises_64_words() {
    let blob = decoded_blob();
    assert_eq!(blob.len(), 524);
    assert_eq!(
        u32::from_le_bytes(blob[0..4].try_into().unwrap()),
        64,
        "a 2048-bit modulus is 64 32-bit words"
    );
}

#[test]
fn encoded_modulus_bytes_reconstruct_n_little_endian() {
    let blob = decoded_blob();
    assert_eq!(
        BigUint::from_bytes_le(&blob[8..264]),
        *test_public_key().n(),
        "bytes 8..264 must be the modulus, little-endian"
    );
}

#[test]
fn encoded_n0inv_times_n0_is_minus_one_mod_2_32() {
    let blob = decoded_blob();
    let n0inv = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    let n0 = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    assert_eq!(
        n0inv.wrapping_mul(n0),
        u32::MAX,
        "n0inv must be the negated inverse of the modulus' low word mod 2^32"
    );
}

#[test]
fn n0inv_holds_for_any_low_word_not_just_the_fixture_key() {
    // The inverse is lifted iteratively, and a lift too few is right
    // for about half of all moduli — including, as it happens, the
    // fixture key. One key cannot pin this; a spread of low words can.
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    for _ in 0..64 {
        let low = rng.next_u32() | 1;
        let n = (BigUint::from(1u32) << 2047usize) | BigUint::from(low);
        let key = RsaPublicKey::new_unchecked(n, BigUint::from(65537u32));

        let blob = decoded_blob_of(&key);
        let n0inv = u32::from_le_bytes(blob[4..8].try_into().unwrap());

        assert_eq!(
            n0inv.wrapping_mul(low),
            u32::MAX,
            "n0inv is wrong for low word {low:#010x}"
        );
    }
}

#[test]
fn encoded_rr_equals_two_to_the_4096_mod_n() {
    let blob = decoded_blob();
    let n = test_public_key().n().clone();
    let rr = (BigUint::from(1u32) << 4096usize) % &n;
    assert_eq!(
        BigUint::from_bytes_le(&blob[264..520]),
        rr,
        "rr must be R^2 mod n with R = 2^2048"
    );
}

#[test]
fn encoded_exponent_field_is_65537_little_endian() {
    let blob = decoded_blob();
    assert_eq!(&blob[520..524], &65537u32.to_le_bytes());
}

#[test]
fn a_key_that_is_not_2048_bits_is_rejected() {
    // 2^1023 + 1: odd, exactly 1024 bits. Composite is fine — only the
    // size is under test, and `new_unchecked` skips primality anyway.
    let n = (BigUint::from(1u32) << 1023usize) + BigUint::from(1u32);
    let key = RsaPublicKey::new_unchecked(n, BigUint::from(65537u32));
    let err = encode_public_key(&key, TEST_NAME).unwrap_err();
    assert!(
        matches!(err, KeyError::UnsupportedModulus(1024)),
        "expected UnsupportedModulus(1024), got {err:?}"
    );
}

#[test]
fn an_exponent_wider_than_u32_is_rejected() {
    let key = RsaPublicKey::new_unchecked(test_public_key().n().clone(), BigUint::from(1u64 << 33));
    let err = encode_public_key(&key, TEST_NAME).unwrap_err();
    assert!(
        matches!(err, KeyError::UnsupportedExponent),
        "expected UnsupportedExponent, got {err:?}"
    );
}

#[test]
fn a_nul_cr_or_lf_in_the_name_never_reaches_the_output() {
    for name in ["unit\0test", "unit\rtest", "unit\ntest"] {
        let err = encode_public_key(&test_public_key(), name).unwrap_err();
        assert!(
            matches!(err, KeyError::InvalidName),
            "name {name:?} must be rejected, got {err:?}"
        );
    }
}

#[test]
fn a_name_too_long_for_one_auth_packet_is_rejected() {
    // The blob rides in a single AUTH message. A name past that limit
    // builds a key that signs perfectly and then fails only at first
    // connect, on the one exchange that carries the public key.
    let key = test_public_key();
    let blob = encode_public_key(&key, "").unwrap().len();
    // What is left for the name once the blob, its space and the
    // wire form's NUL are paid for.
    let longest = crate::base::protocol::command::MAX_PAYLOAD as usize - blob - 2;

    let fits = encode_public_key(&key, &"x".repeat(longest)).unwrap();
    assert_eq!(
        fits.len() + 1,
        crate::base::protocol::command::MAX_PAYLOAD as usize,
        "the longest accepted name fills the packet exactly"
    );

    let err = encode_public_key(&key, &"x".repeat(longest + 1)).unwrap_err();
    assert!(
        matches!(err, KeyError::NameTooLong(len) if len == longest + 1),
        "expected NameTooLong, got {err:?}"
    );
}

#[test]
fn an_empty_name_yields_a_bare_blob_without_trailing_space() {
    let out = encode_public_key(&test_public_key(), "").unwrap();
    assert_eq!(out.len(), 700, "just the base64 token");
    assert!(!out.contains(&b' '));
}

#[test]
fn encoding_matches_the_reference_adb_keygen_output() {
    let out = encode_public_key(&test_public_key(), TEST_NAME).unwrap();
    let mut expected = Vec::from(GOLDEN_PUB_B64.as_bytes());
    expected.extend_from_slice(b" unit@test");
    assert_eq!(
        out, expected,
        "must be byte-identical to the adbkey.pub line adb keygen writes"
    );
}

// ---------------------------------------------------------------------------
// Tests: the key itself
// ---------------------------------------------------------------------------

#[test]
fn from_pkcs8_pem_caches_a_nul_terminated_wire_key() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let mut expected = encode_public_key(&test_public_key(), TEST_NAME).unwrap();
    expected.push(b'\0');
    assert_eq!(key.public_key_wire(), expected);
    assert_eq!(
        key.public_key(),
        expected,
        "the Authenticator path must hand the device the same bytes"
    );
    assert_eq!(
        key.public_key_wire().iter().filter(|&&b| b == 0).count(),
        1,
        "exactly one terminating NUL"
    );
}

#[test]
fn from_pkcs8_der_agrees_with_from_pkcs8_pem() {
    let from_pem = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();
    let der = from_pem.to_pkcs8_der().unwrap();

    let from_der = AdbKey::from_pkcs8_der(der.as_bytes(), &mut test_rng(), TEST_NAME).unwrap();
    assert_eq!(from_der.public_key_wire(), from_pem.public_key_wire());
}

#[test]
fn sign_produces_a_signature_the_rsa_crate_verifies() {
    let mut key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();
    let token = [0x5au8; 20];

    let signature = now(key.sign(&token)).unwrap();

    let verifying = VerifyingKey::<Sha1>::new(test_public_key());
    verifying
        .verify_prehash(&token, &Signature::try_from(signature.as_slice()).unwrap())
        .expect("adbd verifies the token this way");
}

#[test]
fn sign_rejects_a_token_that_is_not_a_sha1_prehash() {
    let mut key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let err = now(key.sign(b"tooshort")).unwrap_err();

    assert!(
        matches!(err, KeyError::InvalidToken(8)),
        "a short token must be refused rather than signed into a malformed DigestInfo, got {err:?}"
    );
}

#[test]
fn to_pkcs8_pem_round_trips_to_the_same_wire_key() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let pem = key.to_pkcs8_pem().unwrap();

    assert!(
        pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "adb keygen writes PKCS#8, and so must we"
    );
    let reloaded = AdbKey::from_pkcs8_pem(&pem, &mut test_rng(), TEST_NAME).unwrap();
    assert_eq!(reloaded.public_key_wire(), key.public_key_wire());
}

#[test]
fn to_pkcs8_der_round_trips_to_the_same_wire_key() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let der = key.to_pkcs8_der().unwrap();

    let reloaded = AdbKey::from_pkcs8_der(der.as_bytes(), &mut test_rng(), TEST_NAME).unwrap();
    assert_eq!(reloaded.public_key_wire(), key.public_key_wire());
}

#[test]
fn a_malformed_pkcs8_key_is_rejected() {
    let err = AdbKey::from_pkcs8_pem(
        "-----BEGIN PRIVATE KEY-----\nnope\n",
        &mut test_rng(),
        TEST_NAME,
    )
    .unwrap_err();
    assert!(
        matches!(err, KeyError::Pkcs8(_)),
        "expected Pkcs8, got {err:?}"
    );
}

#[test]
fn debug_shows_the_public_key_and_never_the_private_one() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let shown = format!("{key:?}");

    assert!(
        shown.contains("unit@test"),
        "the public key line identifies the key: {shown}"
    );
    let secret = format!("{}", rsa::traits::PrivateKeyParts::d(key.private_key()));
    assert!(
        !shown.contains(&secret[..32]),
        "rsa's own Debug prints the private exponent; ours must not"
    );
}

#[test]
fn key_error_display_names_each_failure() {
    assert_eq!(
        format!("{}", KeyError::InvalidName),
        "key name contains a NUL, CR or LF"
    );
    assert_eq!(
        format!("{}", KeyError::UnsupportedModulus(1024)),
        "unsupported modulus size: 1024 bits, need 2048"
    );
    assert_eq!(
        format!("{}", KeyError::NameTooLong(9)),
        "key name of 9 bytes leaves the public key too large for one AUTH packet"
    );
    assert_eq!(
        format!("{}", KeyError::UnsupportedExponent),
        "public exponent is not an odd 32-bit integer of at least 3"
    );
    assert_eq!(
        format!("{}", KeyError::InvalidToken(8)),
        "expected a 20-byte SHA-1 prehash token, got 8"
    );

    // The wrapped errors only implement `Error` under their own std
    // features, so they reach the reader through Display; assert the
    // label rather than upstream's wording.
    let pkcs8 = format!("{}", KeyError::Pkcs8(rsa::pkcs8::Error::KeyMalformed));
    assert!(pkcs8.starts_with("PKCS#8: "), "got {pkcs8}");
    let rsa_err = format!("{}", KeyError::Rsa(rsa::Error::MessageTooLong));
    assert!(rsa_err.starts_with("RSA: "), "got {rsa_err}");
    let pkcs1 = format!("{}", KeyError::Pkcs1(rsa::pkcs1::Error::Version));
    assert!(pkcs1.starts_with("PKCS#1: "), "got {pkcs1}");
    assert_eq!(
        format!("{}", KeyError::EvenModulus),
        "modulus is even, so it is not an RSA modulus"
    );
}

// ---------------------------------------------------------------------------
// Tests: the flash record
// ---------------------------------------------------------------------------

#[test]
fn a_key_record_round_trips_through_encode_and_decode() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();
    let der = key.to_pkcs8_der().unwrap();

    let record = encode_key_record(der.as_bytes()).unwrap();

    assert_eq!(
        decode_key_record(&record),
        Some(der.as_bytes()),
        "what was stored must come back byte-for-byte"
    );
    assert_eq!(
        AdbKey::from_pkcs8_der(
            decode_key_record(&record).unwrap(),
            &mut test_rng(),
            TEST_NAME
        )
        .unwrap()
        .public_key_wire(),
        key.public_key_wire()
    );
}

#[test]
fn a_record_with_nothing_in_it_is_still_a_record() {
    // A header and no payload is well formed — the shortest buffer the
    // decoder may accept, one byte below which it must not.
    let empty = encode_key_record(b"").unwrap();

    assert_eq!(decode_key_record(&empty), Some(&[][..]));
    assert_eq!(decode_key_record(&empty[..empty.len() - 1]), None);
}

#[test]
fn a_record_decodes_from_a_buffer_holding_trailing_flash_bytes() {
    let mut record = encode_key_record(b"\x01\x02\x03\x04").unwrap();
    record.extend_from_slice(&[0xFF; 64]);

    assert_eq!(
        decode_key_record(&record),
        Some(&b"\x01\x02\x03\x04"[..]),
        "a sector read is longer than the record it holds"
    );
}

#[test]
fn erased_flash_or_a_damaged_record_is_rejected() {
    assert_eq!(decode_key_record(&[0xFF; 128]), None, "erased flash");
    assert_eq!(decode_key_record(&[]), None, "nothing at all");

    let record = encode_key_record(b"payload").unwrap();
    assert_eq!(
        decode_key_record(&record[..record.len() - 1]),
        None,
        "payload shorter than the length says"
    );
    assert_eq!(
        decode_key_record(&record[..4]),
        None,
        "header itself truncated"
    );

    let mut foreign = record.clone();
    foreign[0] = b'X';
    assert_eq!(decode_key_record(&foreign), None, "foreign magic");

    let mut future = record.clone();
    future[7] = 0x03;
    assert_eq!(decode_key_record(&future), None, "unknown format version");
}

#[test]
fn a_record_torn_by_a_power_loss_is_rejected_by_its_checksum() {
    // The length and magic survive a write cut short partway through
    // the payload; the sector's erased tail supplies plausible bytes.
    let mut torn = encode_key_record(b"a private key, most of it")
        .unwrap()
        .to_vec();
    let tail = torn.len() - 4;
    torn[tail..].fill(0xFF);

    assert_eq!(
        decode_key_record(&torn),
        None,
        "a half-written key must read as no key, not as a corrupt one"
    );

    let mut flipped = encode_key_record(b"a private key").unwrap().to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(decode_key_record(&flipped), None, "a single flipped bit");
}

#[test]
fn the_record_header_is_the_one_already_written_to_flash() {
    // Persisted format: a change here strands every device that holds
    // a key, so the bytes are pinned rather than left to round-trip.
    let record = encode_key_record(b"123456789").unwrap();

    assert_eq!(&record[..8], b"ADBKEY\0\x02", "magic and version");
    assert_eq!(&record[8..12], &9u32.to_le_bytes(), "payload length");
    assert_eq!(
        &record[12..16],
        &0xCBF4_3926u32.to_le_bytes(),
        "CRC-32 of the standard check string"
    );
    assert_eq!(&record[16..], b"123456789");
}

#[test]
fn generate_yields_a_2048_bit_key_with_e_65537_that_signs_and_encodes() {
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    let mut key = AdbKey::generate(&mut rng, TEST_NAME).unwrap();

    let public = key.private_key().to_public_key();
    assert_eq!(public.n().bits(), 2048);
    assert_eq!(*public.e(), BigUint::from(65537u32));

    let token = [0x11u8; 20];
    let signature = now(key.sign(&token)).unwrap();
    VerifyingKey::<Sha1>::new(public)
        .verify_prehash(&token, &Signature::try_from(signature.as_slice()).unwrap())
        .expect("a generated key must sign what adbd can verify");

    let wire = key.public_key_wire();
    assert_eq!(wire.last(), Some(&0));
    let space = wire.iter().position(|&b| b == b' ').unwrap();
    let blob = Base64::decode_vec(core::str::from_utf8(&wire[..space]).unwrap()).unwrap();
    assert_eq!(u32::from_le_bytes(blob[0..4].try_into().unwrap()), 64);
}

// ---------------------------------------------------------------------------
// Tests: keys the format cannot carry
// ---------------------------------------------------------------------------

#[test]
fn an_even_modulus_is_rejected_rather_than_given_a_meaningless_n0inv() {
    // The Montgomery constant is defined only for an odd modulus; the
    // lifting loop happily returns a wrong answer for an even one.
    let even = test_public_key().n() - BigUint::from(1u32);
    let key = RsaPublicKey::new_unchecked(even, BigUint::from(65537u32));

    let err = encode_public_key(&key, TEST_NAME).unwrap_err();

    assert!(
        matches!(err, KeyError::EvenModulus),
        "expected EvenModulus, got {err:?}"
    );
}

#[test]
fn a_degenerate_exponent_is_rejected() {
    // e = 1 makes every signature verifiable by anyone; 0 and even
    // exponents are not RSA exponents at all.
    for e in [0u32, 1, 2, 4, 65536] {
        let key = RsaPublicKey::new_unchecked(test_public_key().n().clone(), BigUint::from(e));
        let err = encode_public_key(&key, TEST_NAME).unwrap_err();
        assert!(
            matches!(err, KeyError::UnsupportedExponent),
            "exponent {e} must be rejected, got {err:?}"
        );
    }
}

#[test]
fn an_exponent_filling_the_whole_field_is_accepted() {
    // Four bytes is the widest the struct can hold, not one too many.
    let e = 0x0100_0001u32;
    let key = RsaPublicKey::new_unchecked(test_public_key().n().clone(), BigUint::from(e));

    let blob = decoded_blob_of(&key);

    assert_eq!(&blob[520..524], &e.to_le_bytes());
}

#[test]
fn the_smallest_exponent_adb_uses_is_accepted() {
    let key = RsaPublicKey::new_unchecked(test_public_key().n().clone(), BigUint::from(3u32));

    let blob = decoded_blob_of(&key);

    assert_eq!(&blob[520..524], &3u32.to_le_bytes());
}

/// A CSPRNG that fails the test if it is drawn from at all.
struct UnusedRng;

impl RngCore for UnusedRng {
    fn next_u32(&mut self) -> u32 {
        panic!("the RNG was drawn from before the cheap checks ran")
    }
    fn next_u64(&mut self) -> u64 {
        self.next_u32() as u64
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        let _ = self.next_u32();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for UnusedRng {}

#[test]
fn generate_checks_the_name_before_spending_minutes_on_a_key() {
    // On a microcontroller the generation is the expensive part and
    // the rejected key is unrecoverable, so the name goes first.
    let err = AdbKey::generate(&mut UnusedRng, "unit@test\n").unwrap_err();

    assert!(
        matches!(err, KeyError::InvalidName),
        "expected InvalidName, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Tests: one key, several connections
// ---------------------------------------------------------------------------

#[test]
fn a_borrowed_key_authenticates_as_the_key_itself() {
    let mut key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();
    let expected = key.public_key_wire().to_vec();
    let token = [0x5au8; 20];

    // Takes the authenticator by value, the way `Connection::connect`
    // does — so passing `&mut key` goes through the borrowed impl.
    fn connect_like<A: Authenticator>(mut auth: A, token: &[u8]) -> (Vec<u8>, Vec<u8>)
    where
        A::Error: core::fmt::Debug,
    {
        let key = auth.public_key().to_vec();
        (now(auth.sign(token)).unwrap(), key)
    }

    let (first, sent) = connect_like(&mut key, &token);
    let (second, sent_again) = connect_like(&mut key, &token);

    assert_eq!(sent, expected, "the borrow presents the same public key");
    assert_eq!(sent_again, expected);
    assert_eq!(
        first, second,
        "RSA PKCS#1 v1.5 signatures are deterministic"
    );
    VerifyingKey::<Sha1>::new(test_public_key())
        .verify_prehash(&token, &Signature::try_from(first.as_slice()).unwrap())
        .expect("a borrowed key signs as the key it borrows");
}

#[test]
fn the_public_key_line_is_the_wire_key_without_its_terminator() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let line = key.public_key_line();

    assert_eq!(
        line,
        &key.public_key_wire()[..key.public_key_wire().len() - 1]
    );
    assert!(!line.contains(&0), "a key file carries no NUL");
    assert_eq!(
        line,
        encode_public_key(&test_public_key(), TEST_NAME).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Tests: the encodings adb has written over the years
// ---------------------------------------------------------------------------

#[test]
fn from_pkcs1_pem_loads_the_same_key_as_pkcs8() {
    // What `adb` wrote before it moved to PKCS#8, and what
    // `openssl genrsa -traditional` still writes.
    let pkcs8 = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();

    let pkcs1 = AdbKey::from_pkcs1_pem(TEST_KEY_PKCS1_PEM, &mut test_rng(), TEST_NAME).unwrap();

    assert_eq!(
        pkcs1.public_key_wire(),
        pkcs8.public_key_wire(),
        "one key in two encodings is one identity"
    );
}

#[test]
fn a_malformed_pkcs1_key_is_rejected() {
    let err = AdbKey::from_pkcs1_pem(
        "-----BEGIN RSA PRIVATE KEY-----\nnope\n",
        &mut test_rng(),
        TEST_NAME,
    )
    .unwrap_err();

    assert!(
        matches!(err, KeyError::Pkcs1(_)),
        "expected Pkcs1, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Tests: blinding
// ---------------------------------------------------------------------------

#[test]
fn signing_draws_on_the_blinding_generator() {
    // A signature is deterministic, so blinding leaves no trace in the
    // output: what it does leave is a consumed stretch of the key's own
    // generator. Losing that means the private-key operation went out
    // unmasked over an input the peer chose.
    let mut key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();
    let before = key.blinding.get_word_pos();

    now(key.sign(&[0x11u8; 20])).unwrap();

    assert_ne!(
        key.blinding.get_word_pos(),
        before,
        "the signature must be blinded, and blinding costs randomness"
    );
}

#[test]
fn a_refused_token_spends_no_randomness() {
    let mut key = AdbKey::from_pkcs8_pem(TEST_KEY_PEM, &mut test_rng(), TEST_NAME).unwrap();
    let before = key.blinding.get_word_pos();

    now(key.sign(b"tooshort")).unwrap_err();

    assert_eq!(key.blinding.get_word_pos(), before);
}

#[test]
fn a_payload_the_length_field_cannot_describe_is_refused() {
    // The check guards a 64-bit host; on a 32-bit target no `usize`
    // can overflow the field, so there is nothing to reject.
    #[cfg(target_pointer_width = "64")]
    {
        let too_big = u32::MAX as usize + 1;
        let err = crate::keys::record::header(too_big, 0).unwrap_err();
        assert!(
            matches!(err, KeyError::PayloadTooLarge(len) if len == too_big),
            "expected PayloadTooLarge, got {err:?}"
        );
    }

    assert!(crate::keys::record::header(u32::MAX as usize, 0).is_ok());
}
