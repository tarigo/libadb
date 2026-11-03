//! [`SyncError`]: what the sync service fails with.

use alloc::vec::Vec;
use core::fmt;

use crate::error::Error;

/// What the sync service answered instead of what was asked: a `FAIL`,
/// a reply the session did not expect, or an errno in a v2 stat or
/// listing.
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
        }
    }
}

impl core::error::Error for SyncError {}

impl<E> From<SyncError> for Error<E> {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}
