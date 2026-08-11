use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLengthPrefix,
    InvalidProtobuf,
    InvalidUtf8,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLengthPrefix => f.write_str("invalid hex length prefix"),
            Self::InvalidProtobuf => f.write_str("invalid protobuf"),
            Self::InvalidUtf8 => f.write_str("invalid utf-8 in protobuf string"),
        }
    }
}

impl core::error::Error for DecodeError {}

pub fn parse_hex4(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    let mut value: u32 = 0;
    for &b in &buf[..4] {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            _ => return None,
        };
        value = value * 16 + digit;
    }
    Some(value)
}

pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &b) in buf.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

const WIRE_VARINT: u64 = 0;
const WIRE_FIXED64: u64 = 1;
const WIRE_LEN_DELIMITED: u64 = 2;
const WIRE_FIXED32: u64 = 5;

pub fn skip_field(buf: &[u8], wire_type: u64) -> Option<usize> {
    match wire_type {
        WIRE_VARINT => decode_varint(buf).map(|(_, c)| c),
        WIRE_FIXED64 => (buf.len() >= 8).then_some(8),
        WIRE_LEN_DELIMITED => {
            let (len, c) = decode_varint(buf)?;
            let len = usize::try_from(len).ok()?;
            let total = c.checked_add(len)?;
            (total <= buf.len()).then_some(total)
        }
        WIRE_FIXED32 => (buf.len() >= 4).then_some(4),
        _ => None,
    }
}

pub fn read_bytes(buf: &[u8]) -> Result<(&[u8], usize), DecodeError> {
    let (len, c) = decode_varint(buf).ok_or(DecodeError::InvalidProtobuf)?;
    let len = usize::try_from(len).map_err(|_| DecodeError::InvalidProtobuf)?;
    let end = c.checked_add(len).ok_or(DecodeError::InvalidProtobuf)?;
    if end > buf.len() {
        return Err(DecodeError::InvalidProtobuf);
    }
    Ok((&buf[c..end], end))
}

pub fn read_str(buf: &[u8]) -> Result<(&str, usize), DecodeError> {
    let (bytes, consumed) = read_bytes(buf)?;
    let s = core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
    Ok((s, consumed))
}

pub fn read_string(buf: &[u8]) -> Result<(String, usize), DecodeError> {
    let (s, consumed) = read_str(buf)?;
    Ok((s.into(), consumed))
}

pub fn read_varint(buf: &[u8]) -> Result<(u64, usize), DecodeError> {
    decode_varint(buf).ok_or(DecodeError::InvalidProtobuf)
}

pub fn read_tag(buf: &[u8]) -> Result<(u64, u64, usize), DecodeError> {
    let (tag, consumed) = decode_varint(buf).ok_or(DecodeError::InvalidProtobuf)?;
    Ok((tag >> 3, tag & 0x07, consumed))
}

pub fn decode_repeated_field1<T>(
    buf: &[u8],
    mut decode_entry: impl FnMut(&[u8]) -> Result<T, DecodeError>,
) -> Result<Vec<T>, DecodeError> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < buf.len() {
        let (field, wire, c) = read_tag(&buf[pos..])?;
        pos += c;

        if field == 1 && wire == 2 {
            let (data, c) = read_bytes(&buf[pos..])?;
            pos += c;
            entries.push(decode_entry(data)?);
        } else {
            let skipped = skip_field(&buf[pos..], wire).ok_or(DecodeError::InvalidProtobuf)?;
            pos += skipped;
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex4_valid() {
        assert_eq!(parse_hex4(b"0000"), Some(0));
        assert_eq!(parse_hex4(b"002a"), Some(42));
        assert_eq!(parse_hex4(b"ffff"), Some(65535));
        assert_eq!(parse_hex4(b"00FF"), Some(255));
        assert_eq!(parse_hex4(b"0100"), Some(256));
    }

    #[test]
    fn parse_hex4_invalid() {
        assert_eq!(parse_hex4(b"zzzz"), None);
        assert_eq!(parse_hex4(b"00g0"), None);
        assert_eq!(parse_hex4(b""), None);
        assert_eq!(parse_hex4(b"0"), None);
    }

    #[test]
    fn varint_single_byte() {
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x01]), Some((1, 1)));
        assert_eq!(decode_varint(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn varint_multi_byte() {
        assert_eq!(decode_varint(&[0xAC, 0x02]), Some((300, 2)));
    }

    #[test]
    fn skip_varint_field() {
        assert_eq!(skip_field(&[0xAC, 0x02], 0), Some(2));
    }

    #[test]
    fn skip_length_delimited() {
        assert_eq!(skip_field(&[0x03, b'a', b'b', b'c'], 2), Some(4));
    }

    #[test]
    fn read_string_ok() {
        let buf = &[5, b'h', b'e', b'l', b'l', b'o'];
        let (s, c) = read_string(buf).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(c, 6);
    }

    #[test]
    fn huge_length_rejected() {
        let buf: &[u8] = &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, b'a', b'b', b'c',
        ];
        assert_eq!(skip_field(buf, WIRE_LEN_DELIMITED), None);
        assert!(read_bytes(buf).is_err());
    }
}
