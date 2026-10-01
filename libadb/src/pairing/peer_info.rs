//! What the two sides tell each other once the channel is secret.
//!
//! A fixed 8192-byte block, zero-padded, holding a type byte and a
//! NUL-terminated string. AOSP declares it in
//! `pairing_connection/include/adb/pairing/pairing_connection.h` and
//! refuses anything of a different size.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The whole block, padding included.
pub(crate) const SIZE: usize = 8192;

/// What a `PeerInfo` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerInfoType {
    /// The host's ADB public key, in the same encoding a USB
    /// authorisation sends.
    RsaPublicKey,
    /// The device's GUID, which is also its mDNS service name.
    DeviceGuid,
}

impl PeerInfoType {
    fn code(self) -> u8 {
        match self {
            Self::RsaPublicKey => 0,
            Self::DeviceGuid => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::RsaPublicKey),
            1 => Some(Self::DeviceGuid),
            _ => None,
        }
    }
}

/// Why a `PeerInfo` block could not be built or read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerInfoError {
    /// The block was not exactly 8192 bytes. The peer checks this too,
    /// and closes on anything else.
    Size(usize),
    /// The type byte names nothing we know.
    Kind(u8),
    /// The device sent something other than its GUID.
    Unexpected(PeerInfoType),
    /// The payload was not UTF-8.
    NotUtf8,
    /// The payload runs to the end of the block with no NUL to end it,
    /// which a well-formed block never does.
    Unterminated,
    /// Our payload does not fit the block with its terminator. For the
    /// host's key that means a name, the ` user@host` part, several
    /// kilobytes long.
    TooLong(usize),
}

impl core::fmt::Display for PeerInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Size(n) => write!(f, "peer info is {n} bytes, not {SIZE}"),
            Self::Kind(k) => write!(f, "peer info type {k} is not one we know"),
            Self::Unexpected(t) => write!(f, "device answered with {t:?}, expected its GUID"),
            Self::NotUtf8 => f.write_str("peer info payload is not UTF-8"),
            Self::Unterminated => f.write_str("peer info payload has no terminating NUL"),
            Self::TooLong(n) => write!(f, "peer info payload of {n} bytes does not fit"),
        }
    }
}

impl core::error::Error for PeerInfoError {}

/// Build the block that carries `payload`, zero-padded to full size:
/// the peer checks the decrypted length and closes on any other.
pub(crate) fn encode(kind: PeerInfoType, payload: &[u8]) -> Result<Vec<u8>, PeerInfoError> {
    // One byte for the type, one kept clear: the device reads the
    // payload as a C string.
    if payload.len() > SIZE - 2 {
        return Err(PeerInfoError::TooLong(payload.len()));
    }
    let mut block = vec![0u8; SIZE];
    block[0] = kind.code();
    block[1..1 + payload.len()].copy_from_slice(payload);
    Ok(block)
}

/// Read a block, as the device reads ours: up to the first NUL, which
/// has to be there.
pub(crate) fn decode(block: &[u8]) -> Result<(PeerInfoType, String), PeerInfoError> {
    if block.len() != SIZE {
        return Err(PeerInfoError::Size(block.len()));
    }
    let kind = PeerInfoType::from_code(block[0]).ok_or(PeerInfoError::Kind(block[0]))?;
    let data = &block[1..];
    let end = data
        .iter()
        .position(|&b| b == 0)
        .ok_or(PeerInfoError::Unterminated)?;
    let text = core::str::from_utf8(&data[..end])
        .map_err(|_| PeerInfoError::NotUtf8)?
        .into();
    Ok((kind, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_is_always_the_full_size_whatever_it_carries() {
        let short = encode(PeerInfoType::RsaPublicKey, b"k").unwrap();
        let long = encode(PeerInfoType::RsaPublicKey, &[b'k'; 600]).unwrap();

        assert_eq!(short.len(), SIZE);
        assert_eq!(long.len(), SIZE);
    }

    #[test]
    fn the_type_leads_and_the_payload_is_nul_terminated_by_the_padding() {
        let block = encode(PeerInfoType::RsaPublicKey, b"AAAA user@host").unwrap();

        assert_eq!(block[0], 0);
        assert_eq!(&block[1..15], b"AAAA user@host");
        assert_eq!(block[15], 0, "the padding terminates the string");
        assert!(block[15..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_block_round_trips() {
        let block = encode(PeerInfoType::DeviceGuid, b"adb-1234").unwrap();

        let (kind, text) = decode(&block).unwrap();

        assert_eq!(kind, PeerInfoType::DeviceGuid);
        assert_eq!(text, "adb-1234");
    }

    #[test]
    fn a_block_of_the_wrong_size_is_refused_the_way_the_device_refuses_it() {
        assert_eq!(decode(&[0u8; 8191]), Err(PeerInfoError::Size(8191)));
        assert_eq!(decode(&[0u8; 8193]), Err(PeerInfoError::Size(8193)));
    }

    #[test]
    fn an_unknown_type_is_refused() {
        let mut block = vec![0u8; SIZE];
        block[0] = 9;

        assert_eq!(decode(&block), Err(PeerInfoError::Kind(9)));
    }

    #[test]
    fn a_block_without_its_terminator_is_refused() {
        // Read to the end instead, all 8191 bytes would come back as the
        // device's GUID, from a pairing that went through.
        let mut block = vec![b'a'; SIZE];
        block[0] = PeerInfoType::DeviceGuid.code();

        assert_eq!(decode(&block), Err(PeerInfoError::Unterminated));
    }

    #[test]
    fn a_payload_that_would_lose_its_terminator_is_refused() {
        assert_eq!(
            encode(PeerInfoType::RsaPublicKey, &[b'k'; SIZE - 1]),
            Err(PeerInfoError::TooLong(SIZE - 1))
        );
    }
}
