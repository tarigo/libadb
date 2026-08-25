#![no_main]
//! Fuzz the shell_v2 frame decoder with arbitrary byte streams delivered
//! in arbitrary chunk sizes, exercising the ringbuffer compaction and
//! the large-frame split path.
//!
//! Invariants:
//! * Decoding must never panic for any byte sequence.
//! * A successful decode call must always make progress — either
//!   advance the cursor state or return `None`.
//! * The decoder's internal cursors must stay consistent
//!   (`head <= tail <= rx.len()` at all times).

extern crate alloc;
use alloc::vec;

use arbitrary::Arbitrary;
use libadb::shell::v2::{FrameDecoder, HEADER_SIZE};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    rx_capacity: u8,
    chunk_sizes: Vec<u8>,
    bytes: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let capacity = (input.rx_capacity as usize).max(HEADER_SIZE).min(128);
    let mut rx = vec![0u8; capacity];
    let mut decoder = FrameDecoder::new();

    let mut cursor = 0usize;
    let mut chunk_iter = input.chunk_sizes.iter().copied().cycle();
    let mut steps_budget = 2048usize;

    while cursor < input.bytes.len() && steps_budget > 0 {
        steps_budget -= 1;

        if decoder.tail() == rx.len() {
            decoder.compact(&mut rx);
            if decoder.tail() == rx.len() {
                return;
            }
        }

        let writable = rx.len() - decoder.tail();
        let requested = chunk_iter.next().unwrap_or(1).max(1) as usize;
        let take = requested.min(writable).min(input.bytes.len() - cursor);

        let tail = decoder.tail();
        rx[tail..tail + take].copy_from_slice(&input.bytes[cursor..cursor + take]);
        decoder.commit(take);
        cursor += take;

        loop {
            if steps_budget == 0 {
                return;
            }
            steps_budget -= 1;

            let before = (decoder.head(), decoder.tail(), decoder.large_remaining());
            let produced = match decoder.try_next_frame(&rx) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => return,
            };
            let after = (decoder.head(), decoder.tail(), decoder.large_remaining());

            assert!(decoder.head() <= decoder.tail());
            assert!(decoder.tail() <= rx.len());

            if produced {
                assert_ne!(before, after, "try_next_frame returned Some without progress");
            } else {
                break;
            }
        }
    }
});
