use alloc::vec::Vec;

use zeroize::Zeroizing;

use super::KeyError;

const MAGIC: [u8; 8] = *b"ADBKEY\0\x02";
const HEADER_LEN: usize = MAGIC.len() + 4 + 4;

/// Wrap a PKCS#8 DER key in a record that [`decode_key_record`] can
/// find again on a medium with no filesystem.
///
/// The buffer holds a copy of the private key, so it zeroizes on drop;
/// write it out before dropping it.
///
/// Fails for a payload the 32-bit length field cannot describe — such
/// a record would decode back as a truncated prefix rather than what
/// went in.
pub fn encode_key_record(der: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let header = header(der.len(), crc32(der))?;

    let mut out = Vec::with_capacity(HEADER_LEN + der.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(der);
    Ok(Zeroizing::new(out))
}

/// Recover the DER from a record, or `None` when `bytes` holds erased
/// flash, another format or version, a record cut short, or one whose
/// checksum does not match.
///
/// Trailing bytes past the payload are ignored, so a whole sector may
/// be passed in as read.
pub fn decode_key_record(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < HEADER_LEN || bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(bytes[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap());
    let want = u32::from_le_bytes(bytes[MAGIC.len() + 4..HEADER_LEN].try_into().unwrap());
    let der = bytes[HEADER_LEN..].get(..usize::try_from(len).ok()?)?;
    (crc32(der) == want).then_some(der)
}

pub(super) fn header(payload_len: usize, crc: u32) -> Result<[u8; HEADER_LEN], KeyError> {
    let len = u32::try_from(payload_len).map_err(|_| KeyError::PayloadTooLarge(payload_len))?;

    let mut out = [0u8; HEADER_LEN];
    out[..MAGIC.len()].copy_from_slice(&MAGIC);
    out[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&len.to_le_bytes());
    out[MAGIC.len() + 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
