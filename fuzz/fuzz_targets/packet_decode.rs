#![no_main]
//! Fuzz `Packet::decode` against arbitrary byte streams.
//!
//! Invariants:
//! * Decoding must never panic — any adversarial device/network input is
//!   supposed to surface as a `ProtocolError`, not a crash.
//! * `decode → encode → decode` must yield an equal packet. Byte-equal
//!   roundtrip does not hold because `decode` accepts `data_check == 0`
//!   as "unchecked", whereas `encode` always writes the real checksum.

use bytes::BytesMut;
use libadb::protocol::Packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);

    let packet = match Packet::decode(&mut buf) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return,
    };

    let mut reencoded = BytesMut::new();
    packet
        .encode(&mut reencoded)
        .expect("decoded packets must re-encode");

    let redecoded = Packet::decode(&mut reencoded)
        .expect("re-decoding our own encoding must succeed")
        .expect("re-decoding must yield a full packet");

    assert_eq!(packet, redecoded, "decode/encode/decode must be idempotent");
});
