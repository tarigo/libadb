#[cfg(test)]
mod tests;

use super::super::ids::{ChannelIds, RemoteId};
use super::checksum::payload_checksum;
use super::{command::AuthKind, constant::MAX_PAYLOAD, Command, Message, MESSAGE_SIZE};
use crate::error::ProtocolError;
use bytes::{Buf, Bytes, BytesMut};

#[cfg(test)]
use super::Checksum;
#[cfg(test)]
use bytes::BufMut;

/// An ADB packet: a 24-byte message header and its payload.
///
/// What the two argument fields mean depends on the command — channel
/// ids for `OPEN`/`WRTE`/`OKAY`/`CLSE`, protocol version and maximum
/// payload for `CNXN`. See [`Command`].
///
/// [`decode`](Self::decode) is the entry point for reading packets off
/// a stream; there is no matching whole-buffer encoder, because a
/// packet has to leave as a separate header write and payload write —
/// adbd reads the header with an exact-size read.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// What the packet asks for.
    pub command: Command,
    /// First argument; meaning depends on `command`.
    pub arg0: u32,
    /// Second argument; meaning depends on `command`.
    pub arg1: u32,
    /// Payload, empty for commands that carry none.
    pub data: Bytes,
}

impl Packet {
    pub fn new(command: Command, arg0: u32, arg1: u32, payload: impl Into<Bytes>) -> Self {
        let data = payload.into();
        Self {
            command,
            arg0,
            arg1,
            data,
        }
    }

    /// CLSE for the channel `ids` names.
    pub(crate) fn close(ids: ChannelIds) -> Self {
        Self::new(
            Command::Close,
            ids.local.raw(),
            ids.remote.raw(),
            Bytes::new(),
        )
    }

    /// CLSE refusing the OPEN the device sent from `remote`: there is
    /// no end of ours to name, so `arg0` stays zero.
    pub(crate) fn refuse(remote: RemoteId) -> Self {
        Self::new(Command::Close, 0, remote.raw(), Bytes::new())
    }

    pub fn auth_signature(signature: impl Into<Bytes>) -> Self {
        Self::new(Command::Auth, AuthKind::Signature.into(), 0, signature)
    }

    pub fn auth_public_key(key: impl Into<Bytes>) -> Self {
        Self::new(Command::Auth, AuthKind::PublicKey.into(), 0, key)
    }
}

impl Packet {
    /// Returns `Ok(None)` until a whole packet is buffered. The size
    /// check happens before the payload is awaited, so an oversized
    /// announcement fails instead of growing `buf` to fit it.
    pub fn decode(buf: &mut BytesMut, max_payload: u32) -> Result<Option<Self>, ProtocolError> {
        if buf.len() < MESSAGE_SIZE {
            return Ok(None);
        }

        let mut h = &buf[..MESSAGE_SIZE];
        let message = Message {
            command: h.get_u32_le(),
            arg0: h.get_u32_le(),
            arg1: h.get_u32_le(),
            data_length: h.get_u32_le(),
            data_check: h.get_u32_le(),
            magic: h.get_u32_le(),
        };

        let command = Command::try_from(message.command)
            .map_err(|_| ProtocolError::InvalidCommand(message.command))?;

        if message.magic != command.magic() {
            return Err(ProtocolError::InvalidMagic);
        }

        if message.data_length > max_payload.min(MAX_PAYLOAD) {
            return Err(ProtocolError::PayloadTooLarge);
        }

        let payload_len = message.data_length as usize;
        let total_len = MESSAGE_SIZE + payload_len;

        if buf.len() < total_len {
            return Ok(None);
        }

        let packet_buf = buf.split_to(total_len).freeze();
        let data = packet_buf.slice(MESSAGE_SIZE..);

        if message.data_check != 0 && payload_checksum(&data) != message.data_check {
            return Err(ProtocolError::InvalidChecksum);
        }

        Ok(Some(Self {
            command,
            arg0: message.arg0,
            arg1: message.arg1,
            data,
        }))
    }

    /// Bytes still missing before [`decode`](Self::decode) can produce a
    /// packet: the rest of the header, or the rest of the payload it
    /// announces. Only meaningful after `decode` returned `Ok(None)`,
    /// which is also what bounds the announced length.
    pub fn missing(buf: &[u8]) -> usize {
        if buf.len() < MESSAGE_SIZE {
            return MESSAGE_SIZE - buf.len();
        }
        let data_length = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
        (MESSAGE_SIZE + data_length).saturating_sub(buf.len())
    }

    /// Serialize into one contiguous buffer. Test-only: on the wire a
    /// packet must go out as a separate header write and payload write
    /// (see [`send_pkt`](crate::base::wire::send_pkt)), which is what
    /// adbd's exact-size header read requires.
    ///
    /// `checksum` decides whether `data_check` carries the payload sum
    /// or stays zero: see [`Checksum`].
    #[cfg(test)]
    pub fn encode(&self, dst: &mut BytesMut, checksum: Checksum) -> Result<(), ProtocolError> {
        let message = self.to_message(checksum)?;
        dst.reserve(MESSAGE_SIZE + self.data.len());
        dst.put_u32_le(message.command);
        dst.put_u32_le(message.arg0);
        dst.put_u32_le(message.arg1);
        dst.put_u32_le(message.data_length);
        dst.put_u32_le(message.data_check);
        dst.put_u32_le(message.magic);
        dst.put_slice(&self.data);
        Ok(())
    }

    #[cfg(test)]
    fn to_message(&self, checksum: Checksum) -> Result<Message, ProtocolError> {
        if self.data.len() > MAX_PAYLOAD as usize {
            return Err(ProtocolError::PayloadTooLarge);
        }
        Ok(Message {
            command: self.command.into(),
            arg0: self.arg0,
            arg1: self.arg1,
            data_length: self.data.len() as u32,
            data_check: checksum.of(&self.data),
            magic: self.command.magic(),
        })
    }
}
