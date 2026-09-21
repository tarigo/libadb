//! The packet framing of the pairing protocol.
//!
//! Nothing like the ADB framing that carries a session: six bytes of
//! header, big-endian length, and only two kinds of packet. AOSP calls
//! it `PairingPacketHeader` and keeps it in
//! `pairing_connection/pairing_connection.cpp`.

use alloc::vec::Vec;

/// Header length on the wire. Packed, so six and not eight.
pub(crate) const HEADER_LEN: usize = 6;

/// The only version either side speaks.
pub(crate) const VERSION: u8 = 1;

/// Largest payload a peer will accept: twice a `PeerInfo`.
pub(crate) const MAX_PAYLOAD: usize = 16384;

/// What a pairing packet carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketType {
    /// One side's SPAKE2 message: 32 bytes, always.
    Spake2Msg,
    /// The encrypted `PeerInfo` exchange.
    PeerInfo,
}

impl PacketType {
    fn code(self) -> u8 {
        match self {
            Self::Spake2Msg => 0,
            Self::PeerInfo => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Spake2Msg),
            1 => Some(Self::PeerInfo),
            _ => None,
        }
    }
}

/// Why a header could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// The peer speaks a version of the framing we do not.
    Version(u8),
    /// The packet is of a kind that does not exist.
    Kind(u8),
    /// The payload is empty or larger than either side accepts.
    Length(u32),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "pairing header version {v}, expected {VERSION}"),
            Self::Kind(k) => write!(f, "pairing packet type {k} is not one we know"),
            Self::Length(n) => write!(f, "pairing payload of {n} bytes is out of range"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Serialise a header in front of `payload`.
pub(crate) fn encode(kind: PacketType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(VERSION);
    out.push(kind.code());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Read a header, checking it the way the peer will check ours.
pub(crate) fn decode(header: &[u8; HEADER_LEN]) -> Result<(PacketType, usize), FrameError> {
    if header[0] != VERSION {
        return Err(FrameError::Version(header[0]));
    }
    let kind = PacketType::from_code(header[1]).ok_or(FrameError::Kind(header[1]))?;
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    if len == 0 || len as usize > MAX_PAYLOAD {
        return Err(FrameError::Length(len));
    }
    Ok((kind, len as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_is_six_bytes_with_a_big_endian_length() {
        let framed = encode(PacketType::PeerInfo, &[0xAA; 300]);

        assert_eq!(&framed[..HEADER_LEN], &[1, 1, 0, 0, 0x01, 0x2C]);
        assert_eq!(framed.len(), HEADER_LEN + 300);
    }

    #[test]
    fn a_header_round_trips() {
        for kind in [PacketType::Spake2Msg, PacketType::PeerInfo] {
            let framed = encode(kind, &[0u8; 32]);
            let header: [u8; HEADER_LEN] = framed[..HEADER_LEN].try_into().unwrap();

            assert_eq!(decode(&header), Ok((kind, 32)));
        }
    }

    #[test]
    fn a_header_the_peer_would_refuse_is_refused_here_too() {
        assert_eq!(decode(&[2, 0, 0, 0, 0, 32]), Err(FrameError::Version(2)));
        assert_eq!(decode(&[1, 7, 0, 0, 0, 32]), Err(FrameError::Kind(7)));
        assert_eq!(decode(&[1, 0, 0, 0, 0, 0]), Err(FrameError::Length(0)));
        let over = (MAX_PAYLOAD as u32 + 1).to_be_bytes();
        assert_eq!(
            decode(&[1, 0, over[0], over[1], over[2], over[3]]),
            Err(FrameError::Length(MAX_PAYLOAD as u32 + 1))
        );
    }

    #[test]
    fn the_largest_accepted_payload_is_two_peer_infos() {
        let at_limit = (MAX_PAYLOAD as u32).to_be_bytes();
        let header = [1, 1, at_limit[0], at_limit[1], at_limit[2], at_limit[3]];

        assert_eq!(decode(&header), Ok((PacketType::PeerInfo, MAX_PAYLOAD)));
    }
}
