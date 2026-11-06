use alloc::vec::Vec;
use core::fmt;
use core::ops::{BitOr, BitOrAssign};

/// Size of the basic sync header: `id(4) + arg(4)`.
pub const HEADER_SIZE: usize = 8;

/// Maximum data payload in a single `DATA` message (64 KiB).
pub const SYNC_DATA_MAX: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncId {
    Stat,
    Sta2,
    List,
    Lis2,
    Send,
    Snd2,
    Recv,
    Rcv2,
    Data,
    Done,
    Okay,
    Fail,
    Dent,
    Dnt2,
    Quit,
}

impl SyncId {
    pub(super) const ALL: [Self; 15] = [
        Self::Stat,
        Self::Sta2,
        Self::List,
        Self::Lis2,
        Self::Send,
        Self::Snd2,
        Self::Recv,
        Self::Rcv2,
        Self::Data,
        Self::Done,
        Self::Okay,
        Self::Fail,
        Self::Dent,
        Self::Dnt2,
        Self::Quit,
    ];

    pub(crate) fn as_bytes(self) -> [u8; 4] {
        match self {
            Self::Stat => *b"STAT",
            Self::Sta2 => *b"STA2",
            Self::List => *b"LIST",
            Self::Lis2 => *b"LIS2",
            Self::Send => *b"SEND",
            Self::Snd2 => *b"SND2",
            Self::Recv => *b"RECV",
            Self::Rcv2 => *b"RCV2",
            Self::Data => *b"DATA",
            Self::Done => *b"DONE",
            Self::Okay => *b"OKAY",
            Self::Fail => *b"FAIL",
            Self::Dent => *b"DENT",
            Self::Dnt2 => *b"DNT2",
            Self::Quit => *b"QUIT",
        }
    }

    pub(crate) fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.as_bytes() == bytes)
    }
}

pub(super) const STAT_V1_SIZE: usize = 16;
/// Size of a `STA2` response: the four-byte id plus the body
/// [`parse_stat_v2_body`] decodes.
pub const STAT_V2_SIZE: usize = 72;

/// Size of the body a `STA2` response carries after its id.
pub const STAT_V2_BODY_SIZE: usize = STAT_V2_SIZE - 4;
pub(super) const DENT_V1_SIZE: usize = 20;
pub(super) const DENT_V2_SIZE: usize = 76;

/// A Unix file mode as the sync protocol carries it: the file type and
/// the permission bits in one number, e.g. `0o100644` for a regular
/// file its owner may write and anyone may read.
///
/// `Display` prints it in octal, and `{:#}` adds the `0o`.
///
/// ```
/// use libadb::sync::FileMode;
///
/// let mode = FileMode(0o100644);
/// assert_eq!(mode.to_string(), "100644");
/// assert_eq!(format!("{mode:#}"), "0o100644");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct FileMode(pub u32);

impl fmt::Display for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Octal::fmt(&self.0, f)
    }
}

impl fmt::Debug for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileMode({:#o})", self.0)
    }
}

/// File metadata from a `STAT` (v1) response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatV1 {
    /// Unix file mode (type + permissions).
    pub mode: FileMode,
    /// File size in bytes (truncated to u32).
    pub size: u32,
    /// Modification time in Unix seconds, as the v1 record's unsigned
    /// 32 bits hold it: nothing before 1970 or after 2106.
    /// [`StatV2::mtime`] is signed and 64-bit.
    pub mtime: u32,
}

/// File metadata from a `STA2` (v2) response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatV2 {
    /// Error code from the device (0 on success, errno on failure).
    pub error: u32,
    /// The device the file lives on (`st_dev`).
    pub dev: u64,
    /// The file's inode number.
    pub ino: u64,
    /// Unix file mode (type + permissions).
    pub mode: FileMode,
    /// Hard links to the file.
    pub nlink: u32,
    /// The owner's user id.
    pub uid: u32,
    /// The owner's group id.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Last access, in Unix seconds.
    pub atime: i64,
    /// Last modification, in Unix seconds: signed and 64-bit, where
    /// [`StatV1::mtime`] is unsigned and 32-bit.
    pub mtime: i64,
    /// Last status change, in Unix seconds.
    pub ctime: i64,
}

/// Directory entry from a `LIST` → `DENT` response (v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name, as the device's bytes: not always UTF-8.
    pub name: Vec<u8>,
    /// Unix file mode (type + permissions).
    pub mode: FileMode,
    /// File size in bytes (truncated to u32).
    pub size: u32,
    /// Modification time in Unix seconds, unsigned and 32-bit as in
    /// [`StatV1::mtime`].
    pub mtime: u32,
}

/// Directory entry from a `LIS2` response (v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryV2 {
    /// The entry's name, as the device's bytes: not always UTF-8.
    pub name: Vec<u8>,
    /// The entry's metadata; `stat.error` is non-zero when the device
    /// could not stat it.
    pub stat: StatV2,
}

/// Compression and behaviour flags for `SND2` and `RCV2`, combined
/// with `|`, with at most one compression flag among them.
///
/// Each flag needs the feature it names on top of `sendrecv_v2`. adbd
/// ends the sync service over flags it refuses, so the session checks
/// before it sends anything: a flag the device does not advertise fails
/// with [`Error::MissingFeature`](crate::error::Error::MissingFeature),
/// and what no device takes with
/// [`SyncError::InvalidFlags`](super::SyncError::InvalidFlags).
///
/// libadb neither compresses nor decompresses: with a compression flag
/// set, the `DATA` chunks pushed and pulled are the compressed stream.
///
/// ```
/// use libadb::sync::SyncFlags;
///
/// let flags = SyncFlags::ZSTD | SyncFlags::DRY_RUN;
/// assert_eq!(flags.bits(), 0x8000_0004);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SyncFlags(u32);

impl SyncFlags {
    /// Nothing set: an uncompressed transfer.
    pub const NONE: Self = Self(0);
    /// Brotli compression (`sendrecv_v2_brotli`).
    pub const BROTLI: Self = Self(1);
    /// LZ4 compression (`sendrecv_v2_lz4`).
    pub const LZ4: Self = Self(2);
    /// Zstandard compression (`sendrecv_v2_zstd`).
    pub const ZSTD: Self = Self(4);
    /// Dry-run: validate but do not write (SND2 only;
    /// `sendrecv_v2_dry_run_send`).
    pub const DRY_RUN: Self = Self(0x8000_0000);

    /// The flags as the request carries them.
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub(crate) const fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }
}

impl BitOr for SyncFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for SyncFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
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
        mode: FileMode(u32_at(b, 20)),
        nlink: u32_at(b, 24),
        uid: u32_at(b, 28),
        gid: u32_at(b, 32),
        size: u64_at(b, 36),
        atime: i64_at(b, 44),
        mtime: i64_at(b, 52),
        ctime: i64_at(b, 60),
    }
}
