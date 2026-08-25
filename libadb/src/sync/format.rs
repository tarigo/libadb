use alloc::vec::Vec;

/// Size of the basic sync header: `id(4) + arg(4)`.
pub const HEADER_SIZE: usize = 8;

/// Maximum data payload in a single `DATA` message (64 KiB).
pub const SYNC_DATA_MAX: usize = 64 * 1024;

pub(super) const ID_STAT: [u8; 4] = *b"STAT";
pub(super) const ID_STA2: [u8; 4] = *b"STA2";
pub(super) const ID_LIST: [u8; 4] = *b"LIST";
pub(super) const ID_LIS2: [u8; 4] = *b"LIS2";
pub(super) const ID_SEND: [u8; 4] = *b"SEND";
pub(super) const ID_SND2: [u8; 4] = *b"SND2";
pub(super) const ID_RECV: [u8; 4] = *b"RECV";
pub(super) const ID_RCV2: [u8; 4] = *b"RCV2";
pub(super) const ID_DATA: [u8; 4] = *b"DATA";
pub(super) const ID_DONE: [u8; 4] = *b"DONE";
pub(super) const ID_OKAY: [u8; 4] = *b"OKAY";
pub(super) const ID_FAIL: [u8; 4] = *b"FAIL";
pub(super) const ID_DENT: [u8; 4] = *b"DENT";
pub(super) const ID_DNT2: [u8; 4] = *b"DNT2";
pub(super) const ID_QUIT: [u8; 4] = *b"QUIT";

pub(super) const STAT_V1_SIZE: usize = 16;
/// Size of a `STA2` response: the four-byte id plus the body
/// [`parse_stat_v2_body`] decodes.
pub const STAT_V2_SIZE: usize = 72;

/// Size of the body a `STA2` response carries after its id.
pub const STAT_V2_BODY_SIZE: usize = STAT_V2_SIZE - 4;
pub(super) const DENT_V1_SIZE: usize = 20;
pub(super) const DENT_V2_SIZE: usize = 76;

/// File metadata from a `STAT` (v1) response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatV1 {
    /// Unix file mode (type + permissions).
    pub mode: u32,
    /// File size in bytes (truncated to u32).
    pub size: u32,
    /// Modification time (Unix seconds).
    pub mtime: u32,
}

/// File metadata from a `STA2` (v2) response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatV2 {
    /// Error code from the device (0 on success, errno on failure).
    pub error: u32,
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

/// Directory entry from a `LIST` → `DENT` response (v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

/// Directory entry from a `LIS2` response (v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryV2 {
    pub name: Vec<u8>,
    pub stat: StatV2,
}

/// Compression / behaviour flags for `SND2` and `RCV2`.
pub mod flags {
    pub const NONE: u32 = 0;
    pub const BROTLI: u32 = 1;
    pub const LZ4: u32 = 2;
    pub const ZSTD: u32 = 4;
    /// Dry-run: validate but do not write (SND2 only).
    pub const DRY_RUN: u32 = 0x8000_0000;
}

pub(super) fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

pub(super) fn u64_at(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

pub(super) fn i64_at(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

#[doc(hidden)]
pub(super) fn format_u32(mut n: u32, out: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        out[9] = b'0';
        return &out[9..];
    }
    let mut pos = 10;
    while n > 0 {
        pos -= 1;
        out[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &out[pos..]
}

/// Decode the body of a `STA2` response — everything after its
/// four-byte id.
///
/// Takes a fixed-size array rather than a slice, so a short response
/// cannot reach the field reads: the caller has to establish the length
/// first, which the session does while it waits for the whole record.
pub fn parse_stat_v2_body(b: &[u8; STAT_V2_BODY_SIZE]) -> StatV2 {
    StatV2 {
        error: u32_at(b, 0),
        dev: u64_at(b, 4),
        ino: u64_at(b, 12),
        mode: u32_at(b, 20),
        nlink: u32_at(b, 24),
        uid: u32_at(b, 28),
        gid: u32_at(b, 32),
        size: u64_at(b, 36),
        atime: i64_at(b, 44),
        mtime: i64_at(b, 52),
        ctime: i64_at(b, 60),
    }
}
