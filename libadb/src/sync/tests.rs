use super::*;

#[test]
fn every_sync_id_reads_back_from_its_bytes() {
    for id in SyncId::ALL {
        assert_eq!(SyncId::from_bytes(id.as_bytes()), Some(id));
    }
    assert_eq!(SyncId::Sta2.as_bytes(), *b"STA2");
}

#[test]
fn bytes_that_spell_no_sync_id_are_none() {
    assert_eq!(SyncId::from_bytes(*b"MEOW"), None);
    assert_eq!(SyncId::from_bytes(*b"stat"), None);
}

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
    assert_eq!(stat.mode, FileMode(0o100644));
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
    assert_eq!(SyncFlags::NONE.bits(), 0);
    assert_eq!(SyncFlags::BROTLI.bits(), 1);
    assert_eq!(SyncFlags::LZ4.bits(), 2);
    assert_eq!(SyncFlags::ZSTD.bits(), 4);
    assert_eq!(SyncFlags::DRY_RUN.bits(), 0x8000_0000);
    assert_eq!(SyncFlags::default(), SyncFlags::NONE);
}

#[test]
fn flags_combine_with_or() {
    let mut flags = SyncFlags::LZ4 | SyncFlags::DRY_RUN;
    assert_eq!(flags.bits(), 0x8000_0002);
    flags |= SyncFlags::BROTLI;
    assert_eq!(flags.bits(), 0x8000_0003);
}

#[test]
fn a_data_length_past_any_buffer_is_receive_buffer_full() {
    use crate::base::mock::{now, one_slot, wrte};

    // With its 8-byte header the chunk is 2^32 bytes: past `usize` on a
    // 32-bit target, past the buffer on any.
    let mut header = *b"DATA\0\0\0\0";
    header[4..].copy_from_slice(&(u32::MAX - 7).to_le_bytes());
    let mut conn = one_slot("", &[wrte(1, &header)]);
    let mut buf = [0u8; 16];
    let mut sync = now(open(&mut conn, &mut buf)).unwrap();

    let err = now(sync.recv_next()).unwrap_err();
    assert!(matches!(err, Error::ReceiveBufferFull), "got {err:?}");
}
