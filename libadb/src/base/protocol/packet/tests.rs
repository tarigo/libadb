extern crate std;

use super::super::{constant::MAX_PAYLOAD, packet::Packet, Checksum, Command, MESSAGE_SIZE};
use crate::error::ProtocolError;
use bytes::{BufMut, Bytes, BytesMut};

/// Decode with the library-wide limit; tests that care about a
/// custom cap call `Packet::decode` directly.
fn decode(buf: &mut BytesMut) -> Result<Option<Packet>, ProtocolError> {
    Packet::decode(buf, MAX_PAYLOAD)
}

fn checksum(data: &[u8]) -> u32 {
    data.iter().map(|&b| b as u32).sum()
}

fn magic(command: u32) -> u32 {
    command ^ 0xFFFF_FFFF
}

fn encode_header(
    command: u32,
    arg0: u32,
    arg1: u32,
    data_length: u32,
    data_check: u32,
    magic: u32,
) -> BytesMut {
    let mut buf = BytesMut::with_capacity(MESSAGE_SIZE);
    buf.put_u32_le(command);
    buf.put_u32_le(arg0);
    buf.put_u32_le(arg1);
    buf.put_u32_le(data_length);
    buf.put_u32_le(data_check);
    buf.put_u32_le(magic);
    buf
}

#[test]
fn decode_command_without_payload() {
    let command: u32 = Command::Ready.into();
    let arg0 = 10;
    let arg1 = 20;

    let mut buf = BytesMut::new();
    buf.put_u32_le(command);

    assert_eq!(
        decode(&mut buf),
        Ok(None),
        "buffer smaller than header must yield None"
    );

    buf.put_u32_le(arg0);
    buf.put_u32_le(arg1);
    buf.put_u32_le(0);
    buf.put_u32_le(0);
    buf.put_u32_le(magic(command));

    assert_eq!(
        decode(&mut buf),
        Ok(Some(Packet::new(Command::Ready, arg0, arg1, Bytes::new()))),
        "full header must decode into a ready packet"
    );
}

#[test]
fn decode_command_with_payload() {
    let command: u32 = Command::Open.into();
    let arg0 = 10;
    let arg1 = 0;
    let data = b"shell_v2\0";

    let mut buf = BytesMut::new();
    buf.put_u32_le(command);

    assert_eq!(decode(&mut buf), Ok(None));

    buf.put_u32_le(arg0);
    buf.put_u32_le(arg1);
    buf.put_u32_le(data.len() as u32);
    buf.put_u32_le(checksum(data));
    buf.put_u32_le(magic(command));

    assert_eq!(
        decode(&mut buf),
        Ok(None),
        "header-only buffer must wait for the payload"
    );

    buf.put_slice(b"shel");
    assert_eq!(
        decode(&mut buf),
        Ok(None),
        "partial payload must wait for the rest"
    );

    buf.put_slice(b"l_v2\0");
    assert_eq!(
        decode(&mut buf),
        Ok(Some(Packet::new(
            Command::Open,
            arg0,
            0,
            &b"shell_v2\0"[..]
        )))
    );
}

#[test]
fn encode_then_decode_reproduces_packet_without_payload() {
    let original = Packet::new(Command::Ready, 7, 42, Bytes::new());
    let mut buf = BytesMut::new();
    original.encode(&mut buf, Checksum::Compute).unwrap();
    assert_eq!(buf.len(), MESSAGE_SIZE);
    assert_eq!(decode(&mut buf), Ok(Some(original)));
}

#[test]
fn encode_then_decode_reproduces_packet_with_payload() {
    let original = Packet::new(Command::Write, 1, 2, Bytes::from_static(b"hello, device"));
    let mut buf = BytesMut::new();
    original.encode(&mut buf, Checksum::Compute).unwrap();
    assert_eq!(buf.len(), MESSAGE_SIZE + b"hello, device".len());
    assert_eq!(decode(&mut buf), Ok(Some(original)));
}

#[test]
fn encode_refuses_payload_exceeding_max_payload() {
    let oversized = alloc::vec![0u8; MAX_PAYLOAD as usize + 1];
    let packet = Packet::new(Command::Write, 0, 0, Bytes::from(oversized));
    let mut buf = BytesMut::new();
    assert_eq!(
        packet.encode(&mut buf, Checksum::Compute),
        Err(ProtocolError::PayloadTooLarge)
    );
}

#[test]
fn decode_rejects_bad_magic() {
    let command: u32 = Command::Ready.into();
    let mut buf = encode_header(command, 0, 0, 0, 0, magic(command) ^ 0x1);
    assert_eq!(decode(&mut buf), Err(ProtocolError::InvalidMagic));
}

#[test]
fn decode_rejects_unknown_command() {
    let unknown: u32 = 0xDEAD_BEEF;
    let mut buf = encode_header(unknown, 0, 0, 0, 0, magic(unknown));
    assert_eq!(
        decode(&mut buf),
        Err(ProtocolError::InvalidCommand(unknown))
    );
}

#[test]
fn decode_rejects_bad_checksum_when_nonzero() {
    let command: u32 = Command::Write.into();
    let data = b"payload";
    let wrong_checksum = checksum(data).wrapping_add(1);

    let mut buf = encode_header(
        command,
        1,
        2,
        data.len() as u32,
        wrong_checksum,
        magic(command),
    );
    buf.put_slice(data);

    assert_eq!(decode(&mut buf), Err(ProtocolError::InvalidChecksum));
}

#[test]
fn decode_accepts_zero_checksum_as_unchecked() {
    let command: u32 = Command::Write.into();
    let data = b"payload";

    let mut buf = encode_header(command, 1, 2, data.len() as u32, 0, magic(command));
    buf.put_slice(data);

    assert_eq!(
        decode(&mut buf),
        Ok(Some(Packet::new(
            Command::Write,
            1,
            2,
            Bytes::from_static(data)
        )))
    );
}

#[test]
fn decode_rejects_payload_length_above_max_payload() {
    let command: u32 = Command::Write.into();
    let mut buf = encode_header(command, 0, 0, MAX_PAYLOAD + 1, 0, magic(command));
    assert_eq!(decode(&mut buf), Err(ProtocolError::PayloadTooLarge));
}

fn data_check_of(buf: &BytesMut) -> u32 {
    u32::from_le_bytes(buf[16..20].try_into().unwrap())
}

#[test]
fn encode_writes_the_sum_when_asked_to_compute() {
    let packet = Packet::new(Command::Write, 1, 2, Bytes::from_static(b"abc"));
    let mut buf = BytesMut::new();
    packet.encode(&mut buf, Checksum::Compute).unwrap();
    assert_eq!(data_check_of(&buf), 294);
}

#[test]
fn encode_zeroes_data_check_when_skipping() {
    let packet = Packet::new(Command::Write, 1, 2, Bytes::from_static(b"abc"));
    let mut buf = BytesMut::new();
    packet.encode(&mut buf, Checksum::Skip).unwrap();
    assert_eq!(data_check_of(&buf), 0);
    // Everything else is byte-identical to the checksummed form.
    let mut checked = BytesMut::new();
    packet.encode(&mut checked, Checksum::Compute).unwrap();
    assert_eq!(buf[..16], checked[..16]);
    assert_eq!(buf[20..], checked[20..]);
}

#[test]
fn a_skipped_checksum_still_decodes() {
    let original = Packet::new(Command::Write, 1, 2, Bytes::from_static(b"payload"));
    let mut buf = BytesMut::new();
    original.encode(&mut buf, Checksum::Skip).unwrap();
    assert_eq!(decode(&mut buf), Ok(Some(original)));
}
