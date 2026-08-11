use super::*;

#[test]
fn parse_stat_v2_roundtrip() {
    let mut buf = [0u8; 68];
    buf[4..12].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
    buf[12..20].copy_from_slice(&42u64.to_le_bytes());
    buf[20..24].copy_from_slice(&33188u32.to_le_bytes());
    buf[24..28].copy_from_slice(&1u32.to_le_bytes());
    buf[28..32].copy_from_slice(&1000u32.to_le_bytes());
    buf[32..36].copy_from_slice(&1000u32.to_le_bytes());
    buf[36..44].copy_from_slice(&4096u64.to_le_bytes());
    buf[44..52].copy_from_slice(&1700000000i64.to_le_bytes());
    buf[52..60].copy_from_slice(&1700000001i64.to_le_bytes());
    buf[60..68].copy_from_slice(&1700000002i64.to_le_bytes());

    let stat = parse_stat_v2_body(&buf);

    assert_eq!(stat.error, 0);
    assert_eq!(stat.dev, 0x0102030405060708);
    assert_eq!(stat.ino, 42);
    assert_eq!(stat.mode, 33188);
    assert_eq!(stat.nlink, 1);
    assert_eq!(stat.uid, 1000);
    assert_eq!(stat.gid, 1000);
    assert_eq!(stat.size, 4096);
    assert_eq!(stat.atime, 1700000000);
    assert_eq!(stat.mtime, 1700000001);
    assert_eq!(stat.ctime, 1700000002);
}

#[test]
fn parse_stat_v2_error_field() {
    let mut buf = [0u8; 68];
    buf[0..4].copy_from_slice(&2u32.to_le_bytes());
    let stat = parse_stat_v2_body(&buf);
    assert_eq!(stat.error, 2);
}

#[test]
fn sizes_match_protocol() {
    assert_eq!(HEADER_SIZE, 8);
    assert_eq!(STAT_V1_SIZE, 16);
    assert_eq!(STAT_V2_SIZE, 72);
    assert_eq!(DENT_V1_SIZE, 20);
    assert_eq!(DENT_V2_SIZE, 76);
    assert_eq!(SYNC_DATA_MAX, 65536);
}

#[test]
fn flags_values() {
    assert_eq!(flags::NONE, 0);
    assert_eq!(flags::BROTLI, 1);
    assert_eq!(flags::LZ4, 2);
    assert_eq!(flags::ZSTD, 4);
    assert_eq!(flags::DRY_RUN, 0x8000_0000);
}

#[test]
fn format_u32_zero() {
    let mut buf = [0u8; 10];
    assert_eq!(format_u32(0, &mut buf), b"0");
}

#[test]
fn format_u32_typical_mode() {
    let mut buf = [0u8; 10];
    assert_eq!(format_u32(33188, &mut buf), b"33188");
}

#[test]
fn format_u32_max() {
    let mut buf = [0u8; 10];
    assert_eq!(format_u32(u32::MAX, &mut buf), b"4294967295");
}

#[test]
fn format_u32_single_digit() {
    let mut buf = [0u8; 10];
    assert_eq!(format_u32(7, &mut buf), b"7");
}
