//! Self-describing container for a key kept on a raw medium.
//!
//! A microcontroller stores its key in flash, where "no key yet" reads
//! back as erased bytes, a read spans a whole sector, and a write
//! interrupted by a power loss leaves a record half written. Framing
//! the DER with a magic, a length and a checksum lets the firmware tell
//! a stored key from erased, foreign or torn contents before handing
//! anything to a parser.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use super::KeyError;

/// Magic and format version. The last byte is the version, and it is
/// compared as part of the magic: a record written by another version
/// reads back as no record at all.
const MAGIC: [u8; 8] = *b"ADBKEY\0\x02";
/// Magic plus the 32-bit payload length and its CRC-32.
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
    // A cast would truncate a corrupt length into a plausible one
    // where `usize` is narrower than `u32`.
    let der = bytes[HEADER_LEN..].get(..usize::try_from(len).ok()?)?;
    (crc32(der) == want).then_some(der)
}

/// The bytes that precede the payload. Split out so the length can be
/// rejected before anything is allocated — and so the check is
/// reachable by a test without a four-gigabyte buffer.
pub(super) fn header(payload_len: usize, crc: u32) -> Result<[u8; HEADER_LEN], KeyError> {
    let len = u32::try_from(payload_len).map_err(|_| KeyError::PayloadTooLarge(payload_len))?;

    let mut out = [0u8; HEADER_LEN];
    out[..MAGIC.len()].copy_from_slice(&MAGIC);
    out[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&len.to_le_bytes());
    out[MAGIC.len() + 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

/// CRC-32 (IEEE, as in zlib and gzip), computed a bit at a time: this
/// runs once per boot, and a lookup table would cost more flash than
/// the loop saves.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            // The mask is all ones exactly when the bit shifted out was set.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
