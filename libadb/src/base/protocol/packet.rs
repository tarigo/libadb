use super::super::error::ProtocolError;
use super::{
    constant::{AUTH_RSAPUBLICKEY, AUTH_SIGNATURE, MAX_PAYLOAD},
    Checksumable, Command, Message, MESSAGE_SIZE,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// An ADB packet (message + payload).
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub command: Command,
    pub arg0: u32,
    pub arg1: u32,
    pub data: Bytes,
}

impl Checksumable for Bytes {
    type Checksum = u32;

    fn calculate_checksum(&self) -> u32 {
        let mut sum = 0u32;
        for &b in self.as_ref() {
            sum = sum.wrapping_add(b as u32);
        }
        sum
    }
}

impl Checksumable for Packet {
    type Checksum = u32;

    fn calculate_checksum(&self) -> u32 {
        self.data.calculate_checksum()
    }
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

    pub fn close(local_id: u32, remote_id: u32) -> Self {
        Self::new(Command::Close, local_id, remote_id, Bytes::new())
    }

    pub fn auth_signature(signature: impl Into<Bytes>) -> Self {
        Self::new(Command::Auth, AUTH_SIGNATURE, 0, signature)
    }

    pub fn auth_public_key(key: impl Into<Bytes>) -> Self {
        Self::new(Command::Auth, AUTH_RSAPUBLICKEY, 0, key)
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

        if message.data_check != 0 && data.calculate_checksum() != message.data_check {
            return Err(ProtocolError::InvalidChecksum);
        }

        Ok(Some(Self {
            command,
            arg0: message.arg0,
            arg1: message.arg1,
            data,
        }))
    }

    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        let message = self.to_message()?;
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

    fn to_message(&self) -> Result<Message, ProtocolError> {
        if self.data.len() > MAX_PAYLOAD as usize {
            return Err(ProtocolError::PayloadTooLarge);
        }
        Ok(Message {
            command: self.command.into(),
            arg0: self.arg0,
            arg1: self.arg1,
            data_length: self.data.len() as u32,
            data_check: self.data.calculate_checksum(),
            magic: self.command.magic(),
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::super::error::ProtocolError;
    use super::super::{constant::MAX_PAYLOAD, packet::Packet, Command, MESSAGE_SIZE};
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
        original.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), MESSAGE_SIZE);
        assert_eq!(decode(&mut buf), Ok(Some(original)));
    }

    #[test]
    fn encode_then_decode_reproduces_packet_with_payload() {
        let original = Packet::new(Command::Write, 1, 2, Bytes::from_static(b"hello, device"));
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), MESSAGE_SIZE + b"hello, device".len());
        assert_eq!(decode(&mut buf), Ok(Some(original)));
    }

    #[test]
    fn encode_refuses_payload_exceeding_max_payload() {
        let oversized = alloc::vec![0u8; MAX_PAYLOAD as usize + 1];
        let packet = Packet::new(Command::Write, 0, 0, Bytes::from(oversized));
        let mut buf = BytesMut::new();
        assert_eq!(packet.encode(&mut buf), Err(ProtocolError::PayloadTooLarge));
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
}
