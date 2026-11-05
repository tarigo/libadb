//! [`SyncError`]: what a sync request fails with.

use alloc::vec::Vec;
use core::fmt;

use super::SyncFlags;
use crate::error::Error;

/// What a sync request fails with: what the service answered instead of
/// what was asked, be it a `FAIL`, a reply the session did not expect or
/// an errno in a v2 stat or listing, or flags the session did not send
/// because adbd refuses them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncError {
    /// Device returned a `FAIL` response. The message is truncated to
    /// the session buffer when the device sent more than it holds.
    Failed(Vec<u8>),
    /// Unexpected sync response command ID.
    UnexpectedId([u8; 4]),
    /// `STA2` / `LIS2` reported a non-zero error code (device errno).
    RemoteErrno(u32),
    /// Flags adbd refuses whatever the device advertises:
    /// [`DRY_RUN`](SyncFlags::DRY_RUN) on `RCV2`, or more than one
    /// compression flag. adbd would end the service over them, so
    /// nothing was sent and the session stays usable.
    InvalidFlags(SyncFlags),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(msg) => {
                let s = core::str::from_utf8(msg).unwrap_or("<non-utf8>");
                write!(f, "sync: device error: {s}")
            }
            Self::UnexpectedId(id) => {
                let s = core::str::from_utf8(id).unwrap_or("????");
                write!(f, "sync: unexpected response: {s}")
            }
            Self::RemoteErrno(e) => write!(f, "sync: remote errno {e}"),
            Self::InvalidFlags(flags) => write!(f, "sync: invalid flags {:#x}", flags.bits()),
        }
    }
}

impl core::error::Error for SyncError {}

impl<E> From<SyncError> for Error<E> {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}
