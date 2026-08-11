extern crate std;

use alloc::vec;
use alloc::vec::Vec;

use super::decoder::make_frame;
use super::{
    encode_window_size, parse_header, Frame, FrameDecoder, CLOSE_STDIN, EXIT, HEADER_SIZE, STDERR,
    STDIN, STDOUT, WINDOW_SIZE_CHANGE,
};

fn write_header(rx: &mut [u8], offset: usize, id: u8, length: u32) {
    rx[offset] = id;
    rx[offset + 1..offset + 5].copy_from_slice(&length.to_le_bytes());
}

#[test]
fn parse_header_decodes_id_and_little_endian_length() {
    let buf = [STDOUT, 0x04, 0x03, 0x02, 0x01];
    assert_eq!(parse_header(&buf), (STDOUT, 0x0102_0304));
}

#[test]
fn parse_header_accepts_zero_length() {
    let buf = [EXIT, 0, 0, 0, 0];
    assert_eq!(parse_header(&buf), (EXIT, 0));
}

#[test]
fn parse_header_accepts_max_length() {
    let buf = [STDERR, 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(parse_header(&buf), (STDERR, u32::MAX));
}

#[test]
fn encode_window_size_packs_rows_then_cols_and_pads_with_zeros() {
    let bytes = encode_window_size(24, 80);
    assert_eq!(bytes, [24, 0, 80, 0, 0, 0, 0, 0]);
}

#[test]
fn encode_window_size_handles_zero_dimensions() {
    assert_eq!(encode_window_size(0, 0), [0; 8]);
}

#[test]
fn encode_window_size_preserves_full_u16_range() {
    let bytes = encode_window_size(u16::MAX, u16::MAX);
    assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
}

#[test]
fn make_frame_routes_stdout_payload() {
    let frame = make_frame(STDOUT, vec![b'h', b'i']).unwrap();
    assert!(matches!(frame, Frame::Stdout(p) if p == b"hi"));
}

#[test]
fn make_frame_routes_stderr_payload() {
    let frame = make_frame(STDERR, vec![b'e', b'r', b'r']).unwrap();
    assert!(matches!(frame, Frame::Stderr(p) if p == b"err"));
}

#[test]
fn make_frame_extracts_exit_code_from_first_byte() {
    let frame = make_frame(EXIT, vec![42, 99]).unwrap();
    assert!(matches!(frame, Frame::Exit(42)));
}

#[test]
fn make_frame_rejects_empty_exit_payload() {
    use crate::base::error::ProtocolError;
    assert!(matches!(
        make_frame(EXIT, Vec::new()),
        Err(ProtocolError::ShortExitPayload)
    ));
}

#[test]
fn make_frame_wraps_unknown_id_as_other() {
    let frame = make_frame(STDIN, vec![1, 2, 3]).unwrap();
    let Frame::Other { id, payload } = frame else {
        panic!("expected Frame::Other");
    };
    assert_eq!(id, STDIN);
    assert_eq!(payload, vec![1, 2, 3]);
}

#[test]
fn make_frame_wraps_close_stdin_as_other() {
    assert!(matches!(
        make_frame(CLOSE_STDIN, Vec::new()).unwrap(),
        Frame::Other {
            id: CLOSE_STDIN,
            ..
        }
    ));
}

#[test]
fn make_frame_wraps_window_size_change_as_other() {
    assert!(matches!(
        make_frame(WINDOW_SIZE_CHANGE, Vec::new()).unwrap(),
        Frame::Other {
            id: WINDOW_SIZE_CHANGE,
            ..
        }
    ));
}

#[test]
fn header_size_constant_matches_header_buffer() {
    let buf = [0u8; HEADER_SIZE];
    let _ = parse_header(&buf);
}

#[test]
fn frame_decoder_new_starts_at_origin() {
    let d = FrameDecoder::new();
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 0);
    assert_eq!(d.large_remaining(), 0);
}

#[test]
fn frame_decoder_commit_advances_tail() {
    let mut d = FrameDecoder::new();
    d.commit(5);
    d.commit(3);
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 8);
}

#[test]
fn frame_decoder_returns_none_on_empty_buffer() {
    let mut d = FrameDecoder::new();
    let rx = [0u8; 16];
    assert!(d.try_next_raw(&rx).unwrap().is_none());
}

#[test]
fn frame_decoder_returns_none_until_header_complete() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    rx[0] = STDOUT;
    rx[1..4].copy_from_slice(&[3, 0, 0]);
    d.commit(4);
    assert!(d.try_next_raw(&rx).unwrap().is_none());
    assert_eq!(d.tail(), 4);
}

#[test]
fn frame_decoder_returns_none_when_payload_incomplete() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    write_header(&mut rx, 0, STDOUT, 5);
    rx[5..8].copy_from_slice(b"abc");
    d.commit(8);
    assert!(d.try_next_raw(&rx).unwrap().is_none());
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 8);
}

#[test]
fn frame_decoder_decodes_single_complete_frame() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    write_header(&mut rx, 0, STDOUT, 3);
    rx[5..8].copy_from_slice(b"abc");
    d.commit(8);

    let (id, payload) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDOUT);
    assert_eq!(payload, b"abc");
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 0);
}

#[test]
fn frame_decoder_decodes_zero_length_payload() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    write_header(&mut rx, 0, CLOSE_STDIN, 0);
    d.commit(5);

    let (id, payload) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, CLOSE_STDIN);
    assert!(payload.is_empty());
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 0);
}

#[test]
fn frame_decoder_decodes_two_frames_back_to_back() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 32];
    write_header(&mut rx, 0, STDOUT, 2);
    rx[5..7].copy_from_slice(b"hi");
    write_header(&mut rx, 7, STDERR, 3);
    rx[12..15].copy_from_slice(b"err");
    d.commit(15);

    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDOUT);
    assert_eq!(p, b"hi");

    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDERR);
    assert_eq!(p, b"err");

    assert!(d.try_next_raw(&rx).unwrap().is_none());
}

#[test]
fn frame_decoder_leaves_trailing_partial_frame_for_next_call() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 32];
    write_header(&mut rx, 0, STDOUT, 2);
    rx[5..7].copy_from_slice(b"hi");
    write_header(&mut rx, 7, STDERR, 5);
    rx[12..14].copy_from_slice(b"er");
    d.commit(14);

    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDOUT);
    assert_eq!(p, b"hi");

    assert!(d.try_next_raw(&rx).unwrap().is_none());
    assert_eq!(d.head(), 7);
    assert_eq!(d.tail(), 14);
}

#[test]
fn frame_decoder_delivers_oversized_frame_in_chunks() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 8];
    write_header(&mut rx, 0, STDOUT, 10);
    rx[5..8].copy_from_slice(b"abc");
    d.commit(8);

    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDOUT);
    assert_eq!(p, b"abc");
    assert_eq!(d.large_remaining(), 7);
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 0);

    rx[..5].copy_from_slice(b"defgh");
    d.commit(5);
    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDOUT);
    assert_eq!(p, b"defgh");
    assert_eq!(d.large_remaining(), 2);

    rx[..2].copy_from_slice(b"ij");
    d.commit(2);
    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDOUT);
    assert_eq!(p, b"ij");
    assert_eq!(d.large_remaining(), 0);
}

#[test]
fn frame_decoder_registers_oversized_frame_when_only_header_buffered() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 8];
    write_header(&mut rx, 0, STDOUT, 10);
    d.commit(5);

    assert!(d.try_next_raw(&rx).unwrap().is_none());
    assert_eq!(d.large_remaining(), 10);
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 0);
}

#[test]
fn frame_decoder_yields_none_during_oversized_wait_with_empty_buffer() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 8];
    write_header(&mut rx, 0, STDOUT, 10);
    rx[5..8].copy_from_slice(b"abc");
    d.commit(8);

    d.try_next_raw(&rx).unwrap().unwrap();
    assert!(d.try_next_raw(&rx).unwrap().is_none());
    assert_eq!(d.large_remaining(), 7);
}

#[test]
fn frame_decoder_compact_shifts_unread_bytes_to_front() {
    let mut d = FrameDecoder::new();
    let mut rx = [1u8, 2, 3, 4, 5, 6, 7, 8];
    d.commit(7);
    d.head = 3;
    d.compact(&mut rx);
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 4);
    assert_eq!(&rx[..4], &[4, 5, 6, 7]);
}

#[test]
fn frame_decoder_compact_is_noop_when_head_at_zero() {
    let mut d = FrameDecoder::new();
    let mut rx = [1u8, 2, 3, 4];
    d.commit(3);
    d.compact(&mut rx);
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 3);
    assert_eq!(&rx[..3], &[1, 2, 3]);
}

#[test]
fn frame_decoder_decodes_frame_after_compaction() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    write_header(&mut rx, 0, STDOUT, 2);
    rx[5..7].copy_from_slice(b"ok");
    write_header(&mut rx, 7, STDERR, 2);
    rx[12..14].copy_from_slice(b"no");
    d.commit(14);

    d.try_next_raw(&rx).unwrap().unwrap();
    d.compact(&mut rx);
    assert_eq!(d.head(), 0);
    assert_eq!(d.tail(), 7);

    let (id, p) = d.try_next_raw(&rx).unwrap().unwrap();
    assert_eq!(id, STDERR);
    assert_eq!(p, b"no");
}

#[test]
fn frame_decoder_try_next_frame_wraps_raw_into_enum() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    write_header(&mut rx, 0, EXIT, 1);
    rx[5] = 7;
    d.commit(6);

    let frame = d.try_next_frame(&rx).unwrap().unwrap();
    assert!(matches!(frame, Frame::Exit(7)));
}

#[test]
fn frame_decoder_try_next_frame_returns_none_when_incomplete() {
    let mut d = FrameDecoder::new();
    let mut rx = [0u8; 16];
    write_header(&mut rx, 0, STDOUT, 4);
    rx[5..7].copy_from_slice(b"ab");
    d.commit(7);

    assert!(d.try_next_frame(&rx).unwrap().is_none());
}
