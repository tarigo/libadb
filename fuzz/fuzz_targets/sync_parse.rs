#![no_main]
//! Fuzz the pure sync-protocol helpers.
//!
//! `parse_stat_v2_body` takes a fixed-size body, so short inputs are
//! padded with zeros to fill the window. The check is structural: no
//! field read may panic on any bit pattern, and the integer fields must
//! decode as little-endian.

extern crate alloc;

use arbitrary::Arbitrary;
use libadb::sync::{parse_stat_v2_body, STAT_V2_BODY_SIZE};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    stat_body: Vec<u8>,
}

fuzz_target!(|input: Input| {
    fuzz_parse_stat(&input.stat_body);
});

fn fuzz_parse_stat(raw: &[u8]) {
    let mut buf = [0u8; STAT_V2_BODY_SIZE];
    let take = raw.len().min(buf.len());
    buf[..take].copy_from_slice(&raw[..take]);

    let stat = parse_stat_v2_body(&buf);

    let expect_error = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let expect_dev = u64::from_le_bytes(buf[4..12].try_into().unwrap());
    assert_eq!(stat.error, expect_error);
    assert_eq!(stat.dev, expect_dev);
}
