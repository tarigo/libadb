#![no_main]
//! Fuzz the pure sync-protocol helpers.
//!
//! * `parse_stat_v2_body` has a length precondition (`b.len() >= 68`).
//!   We pad short inputs with zeros so the harness can drive every bit
//!   pattern in the 68-byte window without hitting the documented
//!   indexing panic. The check is structural: none of the field reads
//!   should panic on any bit pattern, and integer fields must decode as
//!   little-endian.
//!
//! * `format_u32` must always produce valid ASCII digits that parse
//!   back to the original `u32`.

extern crate alloc;

use arbitrary::Arbitrary;
use libadb::sync::{format_u32, parse_stat_v2_body, STAT_V2_SIZE};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    stat_body: Vec<u8>,
    numbers: Vec<u32>,
}

fuzz_target!(|input: Input| {
    fuzz_parse_stat(&input.stat_body);
    for n in input.numbers {
        fuzz_format_u32_roundtrip(n);
    }
});

fn fuzz_parse_stat(raw: &[u8]) {
    let mut buf = alloc::vec![0u8; STAT_V2_SIZE - 4];
    let take = raw.len().min(buf.len());
    buf[..take].copy_from_slice(&raw[..take]);

    let stat = parse_stat_v2_body(&buf);

    let expect_error = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let expect_dev = u64::from_le_bytes(buf[4..12].try_into().unwrap());
    assert_eq!(stat.error, expect_error);
    assert_eq!(stat.dev, expect_dev);
}

fn fuzz_format_u32_roundtrip(n: u32) {
    let mut out = [0u8; 10];
    let formatted = format_u32(n, &mut out);

    assert!(!formatted.is_empty());
    assert!(formatted.len() <= 10);
    assert!(formatted.iter().all(|b| (b'0'..=b'9').contains(b)));
    assert!(formatted[0] != b'0' || formatted.len() == 1);

    let parsed: u32 = core::str::from_utf8(formatted)
        .expect("format_u32 must emit valid UTF-8 ASCII")
        .parse()
        .expect("format_u32 must emit a parseable decimal");
    assert_eq!(parsed, n);
}
