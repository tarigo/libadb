use bytes::BytesMut;
use embedded_io_async::{Read, Write};

use super::error::{Error, ProtocolError};
use super::protocol::command::Command;
use super::protocol::constant::MAX_PAYLOAD;
use super::protocol::packet::Packet;
use super::protocol::MESSAGE_SIZE;

pub(crate) const RECV_SCRATCH: usize = 4096;

pub(crate) async fn write_all<T: Write>(t: &mut T, buf: &[u8]) -> Result<(), Error<T::Error>> {
    let mut pos = 0;
    while pos < buf.len() {
        match t.write(&buf[pos..]).await {
            Ok(0) => return Err(Error::UnexpectedEof),
            Ok(n) => pos += n,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

pub(crate) async fn send_pkt<T: Write>(t: &mut T, pkt: &Packet) -> Result<(), Error<T::Error>> {
    let mut buf = BytesMut::with_capacity(MESSAGE_SIZE + pkt.data.len());
    pkt.encode(&mut buf)?;
    write_all(t, &buf).await
}

/// Rejects any packet whose announced payload exceeds `max_payload`.
pub(crate) async fn recv_pkt<T: Read>(
    t: &mut T,
    buf: &mut BytesMut,
    max_payload: u32,
) -> Result<Packet, Error<T::Error>> {
    let mut tmp = [0u8; RECV_SCRATCH];
    loop {
        if let Some(pkt) = Packet::decode(buf, max_payload)? {
            return Ok(pkt);
        }
        match t.read(&mut tmp).await {
            Ok(0) => return Err(Error::UnexpectedEof),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

fn payload_checksum(payload: &[u8]) -> u32 {
    let mut sum = 0u32;
    for &b in payload {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

fn encode_header(
    command: Command,
    arg0: u32,
    arg1: u32,
    payload: &[u8],
) -> Result<[u8; MESSAGE_SIZE], ProtocolError> {
    if payload.len() > MAX_PAYLOAD as usize {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let cmd_u32: u32 = command.into();
    let data_length = payload.len() as u32;
    let data_check = payload_checksum(payload);
    let magic = command.magic();
    let mut h = [0u8; MESSAGE_SIZE];
    h[0..4].copy_from_slice(&cmd_u32.to_le_bytes());
    h[4..8].copy_from_slice(&arg0.to_le_bytes());
    h[8..12].copy_from_slice(&arg1.to_le_bytes());
    h[12..16].copy_from_slice(&data_length.to_le_bytes());
    h[16..20].copy_from_slice(&data_check.to_le_bytes());
    h[20..24].copy_from_slice(&magic.to_le_bytes());
    Ok(h)
}

pub(crate) async fn send_raw<T: Write>(
    t: &mut T,
    command: Command,
    arg0: u32,
    arg1: u32,
    payload: &[u8],
) -> Result<(), Error<T::Error>> {
    let header = encode_header(command, arg0, arg1, payload)?;
    write_all(t, &header).await?;
    if !payload.is_empty() {
        write_all(t, payload).await?;
    }
    Ok(())
}

pub(crate) async fn send_okay_to<T: Write>(
    transport: &mut T,
    delayed_ack: bool,
    local_id: u32,
    remote_id: u32,
    wrte_len: usize,
) -> Result<(), Error<T::Error>> {
    let ack = (wrte_len as u32).to_le_bytes();
    let payload: &[u8] = if delayed_ack { &ack } else { &[] };
    send_raw(transport, Command::Ready, local_id, remote_id, payload).await
}
