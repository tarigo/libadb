#![no_main]
//! Fuzz `Packet::decode` against arbitrary byte streams.
//!
//! Invariants:
//! * Decoding must never panic — any adversarial device/network input is
//!   supposed to surface as a `ProtocolError`, not a crash.
//! * Re-encoding what was decoded and decoding that again must yield an
//!   equal packet. The encoder lives here rather than in the crate: on
//!   the wire a packet goes out as a separate header write and payload
//!   write, so `libadb` has no public "one contiguous buffer" encoder to
//!   borrow.

use bytes::BytesMut;
use libadb::protocol::constant::MAX_PAYLOAD;
use libadb::protocol::{Checksum, Packet};
use libfuzzer_sys::fuzz_target;

/// Lay a packet out the way the wire format prescribes: 24-byte header,
/// then payload.
fn encode(packet: &Packet, checksum: Checksum) -> BytesMut {
    let command: u32 = packet.command.into();
    let mut out = BytesMut::with_capacity(24 + packet.data.len());
    out.extend_from_slice(&command.to_le_bytes());
    out.extend_from_slice(&packet.arg0.to_le_bytes());
    out.extend_from_slice(&packet.arg1.to_le_bytes());
    out.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum.of(&packet.data).to_le_bytes());
    out.extend_from_slice(&(command ^ 0xFFFF_FFFF).to_le_bytes());
    out.extend_from_slice(&packet.data);
    out
}

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);

    let packet = match Packet::decode(&mut buf, MAX_PAYLOAD) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return,
    };

    let mut reencoded = encode(&packet, Checksum::Compute);

    let redecoded = Packet::decode(&mut reencoded, MAX_PAYLOAD)
        .expect("re-decoding our own encoding must succeed")
        .expect("re-decoding must yield a full packet");

    assert_eq!(packet, redecoded, "decode/encode/decode must be idempotent");
});
