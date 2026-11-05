//! ADB sync protocol — file operations (stat, list, push, pull).
//!
//! The sync protocol operates over a `sync:\0` channel and provides
//! file-system access on the device.  Each message uses an 8-byte
//! header: `[id: 4 ASCII bytes, arg: u32 LE]`, optionally followed
//! by a variable-length payload.
//!
//! This module supports both legacy (v1) and extended (v2) variants:
//!
//! | Operation | v1 | v2 | Feature |
//! |-----------|----|----|---------|
//! | Stat | `STAT` | `STA2` | `stat_v2` |
//! | List dir | `LIST`→`DENT` | `LIS2` | `ls_v2` |
//! | Pull file | `RECV` | `RCV2` | `sendrecv_v2` |
//! | Push file | `SEND` | `SND2` | `sendrecv_v2` |
//!
//! Each of the [`SyncFlags`] `RCV2` and `SND2` carry needs a feature of
//! its own on top of `sendrecv_v2`.
//!
//! # Buffer sizing
//!
//! [`SyncSession`] uses a caller-provided byte slice as its receive
//! buffer.  The minimum useful size depends on the operation:
//!
//! * **stat / stat_v2**: 72 bytes.
//! * **list / list_v2**: 76 bytes + longest file name.
//! * **recv / send**: [`HEADER_SIZE`] + [`SYNC_DATA_MAX`] = 65 544
//!   bytes to fit the largest `DATA` chunk the device may send.
//!
//! Passing a buffer that is too small yields
//! [`Error::ReceiveBufferFull`] — except for a `FAIL` body, which is
//! truncated to the buffer instead so the device's error is never
//! masked by a buffer complaint.
//!
//! # Examples
//!
//! ```ignore
//! let mut buf = [0u8; 66_000];
//! let mut sync = sync::open(&mut conn, &mut buf).await?;
//!
//! // stat
//! let st = sync.stat_v2("/sdcard/DCIM").await?;
//!
//! // list
//! for entry in sync.list_v2("/sdcard/DCIM").await? {
//!     println!("{}", core::str::from_utf8(&entry.name).unwrap());
//! }
//!
//! // pull (small file)
//! let data = sync.recv("/sdcard/file.txt").await?;
//!
//! // push
//! sync.send("/sdcard/upload.txt", FileMode(0o100644), 0, b"hello").await?;
//!
//! sync.quit().await?;
//! ```

mod error;
mod format;
#[cfg(test)]
mod tests;

pub use error::SyncError;
pub use format::*;

use alloc::vec::Vec;

use crate::base::channel::Channel;
use crate::base::decimal::format_u32;
use crate::base::protocol::features::Feature;
use crate::base::recv_buf::RecvBuf;
use crate::base::session::Session;
use crate::error::Error;
use format::{u32_at, SyncId, DENT_V1_SIZE, DENT_V2_SIZE, STAT_V1_SIZE};

/// What a device has to advertise, on top of `sendrecv_v2`, to take each
/// flag.
const FLAG_FEATURES: [(SyncFlags, Feature); 4] = [
    (SyncFlags::BROTLI, Feature::SendrecvV2Brotli),
    (SyncFlags::LZ4, Feature::SendrecvV2Lz4),
    (SyncFlags::ZSTD, Feature::SendrecvV2Zstd),
    (SyncFlags::DRY_RUN, Feature::SendrecvV2DryRunSend),
];

/// The compression flags, of which adbd takes one at most.
const COMPRESSION: [SyncFlags; 3] = [SyncFlags::BROTLI, SyncFlags::LZ4, SyncFlags::ZSTD];

/// A sync session over an open `sync:\0` channel.
///
/// Provides stat, list, push and pull operations.  Created by [`open`].
/// Multiple operations can be performed on the same session before
/// calling [`quit`](Self::quit).
pub struct SyncSession<'a, 'b, S> {
    channel: Channel<'a, S>,
    rx: RecvBuf<'b>,
}

impl<'a, 'b, S: Session> SyncSession<'a, 'b, S> {
    /// Wrap an already-opened `sync:\0` channel.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < HEADER_SIZE`.
    pub fn new(channel: Channel<'a, S>, buf: &'b mut [u8]) -> Self {
        assert!(
            buf.len() >= HEADER_SIZE,
            "SyncSession buffer must be at least {} bytes",
            HEADER_SIZE,
        );
        Self {
            channel,
            rx: RecvBuf::new(buf),
        }
    }

    /// Fail unless the device takes a v2 transfer with `flags`. adbd
    /// ends the service over flags it refuses, so the session has to
    /// find out before it writes anything.
    fn require_sendrecv_v2(&self, flags: SyncFlags) -> Result<(), Error<S::IoError>> {
        if COMPRESSION.iter().filter(|&&c| flags.contains(c)).count() > 1 {
            return Err(SyncError::InvalidFlags(flags).into());
        }
        self.channel.session.require_feature(Feature::SendrecvV2)?;
        for (flag, feature) in FLAG_FEATURES {
            if flags.contains(flag) {
                self.channel.session.require_feature(feature)?;
            }
        }
        Ok(())
    }

    fn peek_id(&self) -> [u8; 4] {
        self.rx.peek(4).try_into().expect("peeked four bytes")
    }

    fn peek_u32(&self, offset: usize) -> u32 {
        u32_at(self.rx.peek(offset + 4), offset)
    }

    async fn write_header(&mut self, id: SyncId, arg: u32) -> Result<(), Error<S::IoError>> {
        let mut hdr = [0u8; HEADER_SIZE];
        hdr[..4].copy_from_slice(&id.as_bytes());
        hdr[4..8].copy_from_slice(&arg.to_le_bytes());
        self.channel.write(&hdr).await
    }

    /// Write `parts` behind a header that gives their length.
    async fn write_request(
        &mut self,
        id: SyncId,
        parts: &[&[u8]],
    ) -> Result<(), Error<S::IoError>> {
        let arg_len: usize = parts.iter().map(|p| p.len()).sum();
        self.write_message(id, arg_len as u32, parts).await
    }

    /// Write `parts` behind a header carrying `arg`, in one write when
    /// they fit the free part of the receive buffer.
    async fn write_message(
        &mut self,
        id: SyncId,
        arg: u32,
        parts: &[&[u8]],
    ) -> Result<(), Error<S::IoError>> {
        let total = HEADER_SIZE + parts.iter().map(|p| p.len()).sum::<usize>();

        self.rx.compact();
        let window = self.rx.window();

        if total <= window.len() {
            window[..4].copy_from_slice(&id.as_bytes());
            window[4..8].copy_from_slice(&arg.to_le_bytes());
            let mut off = HEADER_SIZE;
            for p in parts {
                window[off..off + p.len()].copy_from_slice(p);
                off += p.len();
            }
            self.channel.write(&window[..total]).await
        } else {
            self.write_header(id, arg).await?;
            for p in parts {
                if !p.is_empty() {
                    self.channel.write(p).await?;
                }
            }
            Ok(())
        }
    }

    async fn read_next_id(&mut self, allowed: &[SyncId]) -> Result<SyncId, Error<S::IoError>> {
        self.rx
            .fill_at_least(&mut self.channel, HEADER_SIZE)
            .await?;
        let raw = self.peek_id();
        match SyncId::from_bytes(raw) {
            Some(SyncId::Fail) => {
                let msg = self.read_fail_body().await?;
                Err(SyncError::Failed(msg).into())
            }
            Some(id) if allowed.contains(&id) => Ok(id),
            _ => Err(SyncError::UnexpectedId(raw).into()),
        }
    }

    async fn read_fail_body(&mut self) -> Result<Vec<u8>, Error<S::IoError>> {
        let msg_len = self.peek_u32(4) as usize;
        self.rx.advance(HEADER_SIZE);
        // The device's message outranks a buffer complaint: keep what
        // fits and drain the rest, so the error surfaces truncated
        // rather than masked by ReceiveBufferFull — and the stream
        // stays consistent for whatever the caller does next.
        let kept = msg_len.min(self.rx.capacity());
        if kept > 0 {
            self.rx.fill_at_least(&mut self.channel, kept).await?;
        }
        let msg = self.rx.take(kept).to_vec();
        let mut left = msg_len - kept;
        while left > 0 {
            let chunk = left.min(self.rx.capacity());
            self.rx.fill_at_least(&mut self.channel, chunk).await?;
            self.rx.advance(chunk);
            left -= chunk;
        }
        Ok(msg)
    }

    /// Stat a file (v1).
    ///
    /// Returns zeroed fields when the path does not exist (v1 has no
    /// error code).
    pub async fn stat(&mut self, path: &str) -> Result<StatV1, Error<S::IoError>> {
        self.rx.compact();
        self.write_request(SyncId::Stat, &[path.as_bytes()]).await?;
        self.read_next_id(&[SyncId::Stat]).await?;

        self.rx
            .fill_at_least(&mut self.channel, STAT_V1_SIZE)
            .await?;
        let mode = FileMode(self.peek_u32(4));
        let size = self.peek_u32(8);
        let mtime = self.peek_u32(12);
        self.rx.advance(STAT_V1_SIZE);
        Ok(StatV1 { mode, size, mtime })
    }

    /// Stat a file (v2).
    ///
    /// Returns full metadata including uid/gid and 64-bit size.
    /// Requires the device to advertise `stat_v2`: one whose banner
    /// does not fails with [`Error::MissingFeature`] before anything is
    /// sent.
    ///
    /// Returns [`SyncError::RemoteErrno`] when the device reports a
    /// non-zero error code (e.g. `ENOENT`).
    pub async fn stat_v2(&mut self, path: &str) -> Result<StatV2, Error<S::IoError>> {
        self.channel.session.require_feature(Feature::StatV2)?;
        self.rx.compact();
        self.write_request(SyncId::Sta2, &[path.as_bytes()]).await?;
        self.read_next_id(&[SyncId::Sta2]).await?;

        self.rx
            .fill_at_least(&mut self.channel, STAT_V2_SIZE)
            .await?;
        let body = &self.rx.peek(STAT_V2_SIZE)[4..];
        let stat = parse_stat_v2_body(body.try_into().expect("checked STAT_V2_SIZE bytes"));
        self.rx.advance(STAT_V2_SIZE);

        if stat.error != 0 {
            return Err(SyncError::RemoteErrno(stat.error).into());
        }
        Ok(stat)
    }

    /// List a directory (v1).
    pub async fn list(&mut self, path: &str) -> Result<Vec<DirEntry>, Error<S::IoError>> {
        self.rx.compact();
        self.write_request(SyncId::List, &[path.as_bytes()]).await?;

        let mut entries = Vec::new();
        loop {
            if self.read_next_id(&[SyncId::Dent, SyncId::Done]).await? == SyncId::Done {
                // adbd closes a listing with a whole `dent` record whose
                // id is DONE, not a bare header — consuming only the
                // head would leave its tail in the stream.
                self.rx
                    .fill_at_least(&mut self.channel, DENT_V1_SIZE)
                    .await?;
                self.rx.advance(DENT_V1_SIZE);
                return Ok(entries);
            }

            self.rx
                .fill_at_least(&mut self.channel, DENT_V1_SIZE)
                .await?;
            let mode = FileMode(self.peek_u32(4));
            let size = self.peek_u32(8);
            let mtime = self.peek_u32(12);
            let namelen = self.peek_u32(16) as usize;
            self.rx.advance(DENT_V1_SIZE);

            self.rx.fill_at_least(&mut self.channel, namelen).await?;
            let name = self.rx.take(namelen).to_vec();

            entries.push(DirEntry {
                name,
                mode,
                size,
                mtime,
            });
        }
    }

    /// List a directory (v2).
    ///
    /// Requires the device to advertise `ls_v2`, failing with
    /// [`Error::MissingFeature`] before anything is sent otherwise.
    /// Entries whose stat failed on the device have a non-zero
    /// `stat.error` field but are still included in the result.
    pub async fn list_v2(&mut self, path: &str) -> Result<Vec<DirEntryV2>, Error<S::IoError>> {
        self.channel.session.require_feature(Feature::LsV2)?;
        self.rx.compact();
        self.write_request(SyncId::Lis2, &[path.as_bytes()]).await?;

        let mut entries = Vec::new();
        loop {
            if self.read_next_id(&[SyncId::Dnt2, SyncId::Done]).await? == SyncId::Done {
                // Same as `list`, with the v2 record size.
                self.rx
                    .fill_at_least(&mut self.channel, DENT_V2_SIZE)
                    .await?;
                self.rx.advance(DENT_V2_SIZE);
                return Ok(entries);
            }

            self.rx
                .fill_at_least(&mut self.channel, DENT_V2_SIZE)
                .await?;
            let body = &self.rx.peek(STAT_V2_SIZE)[4..];
            let stat = parse_stat_v2_body(body.try_into().expect("checked STAT_V2_SIZE bytes"));
            let namelen = self.peek_u32(72) as usize;
            self.rx.advance(DENT_V2_SIZE);

            self.rx.fill_at_least(&mut self.channel, namelen).await?;
            let name = self.rx.take(namelen).to_vec();

            entries.push(DirEntryV2 { name, stat });
        }
    }

    /// Begin a `RECV` (v1) pull.
    pub async fn recv_start(&mut self, path: &str) -> Result<(), Error<S::IoError>> {
        self.rx.compact();
        self.write_request(SyncId::Recv, &[path.as_bytes()]).await
    }

    /// Begin a `RCV2` (v2) pull.
    ///
    /// `flags` combines [`SyncFlags`]; [`SyncFlags::NONE`] pulls
    /// uncompressed. Requires the device to advertise `sendrecv_v2` and
    /// the feature of each flag, failing with [`Error::MissingFeature`]
    /// otherwise. adbd has no dry-run pull and takes one compression flag
    /// at most, so [`SyncFlags::DRY_RUN`] or two compression flags fail
    /// with [`SyncError::InvalidFlags`] whatever the device advertises.
    /// Either way nothing is sent and the session stays usable.
    pub async fn recv_v2_start(
        &mut self,
        path: &str,
        flags: SyncFlags,
    ) -> Result<(), Error<S::IoError>> {
        if flags.contains(SyncFlags::DRY_RUN) {
            return Err(SyncError::InvalidFlags(flags).into());
        }
        self.require_sendrecv_v2(flags)?;
        let path_bytes = path.as_bytes();
        // The header's length stops at the path: `sync_recv_v2` follows
        // it, and opens with the same id.
        self.write_message(
            SyncId::Rcv2,
            path_bytes.len() as u32,
            &[
                path_bytes,
                &SyncId::Rcv2.as_bytes(),
                &flags.bits().to_le_bytes(),
            ],
        )
        .await
    }

    /// Read the next `DATA` chunk from an in-progress recv.
    ///
    /// Returns `Ok(Some(data))` for each chunk and `Ok(None)` when the
    /// device signals `DONE`.  The returned slice references the
    /// internal buffer and is valid until the next method call.
    ///
    /// Must be called after [`recv_start`](Self::recv_start) or
    /// [`recv_v2_start`](Self::recv_v2_start). A chunk that does not
    /// fit the buffer together with its header is
    /// [`Error::ReceiveBufferFull`].
    pub async fn recv_next(&mut self) -> Result<Option<&[u8]>, Error<S::IoError>> {
        self.rx.compact();
        if self.read_next_id(&[SyncId::Data, SyncId::Done]).await? == SyncId::Done {
            self.rx.advance(HEADER_SIZE);
            return Ok(None);
        }

        let data_len = self.peek_u32(4) as usize;
        // On a 32-bit target a length near `u32::MAX` overflows the sum;
        // no buffer holds such a chunk on any target.
        let chunk_len = HEADER_SIZE
            .checked_add(data_len)
            .ok_or(Error::ReceiveBufferFull)?;
        self.rx.fill_at_least(&mut self.channel, chunk_len).await?;
        self.rx.advance(HEADER_SIZE);
        Ok(Some(self.rx.take(data_len)))
    }

    /// Pull a file into memory (v1 `RECV`).
    ///
    /// Convenience wrapper around [`recv_start`](Self::recv_start) +
    /// [`recv_next`](Self::recv_next).  For large files prefer the
    /// streaming API.
    pub async fn recv(&mut self, path: &str) -> Result<Vec<u8>, Error<S::IoError>> {
        self.recv_start(path).await?;
        let mut data = Vec::new();
        while let Some(chunk) = self.recv_next().await? {
            data.extend_from_slice(chunk);
        }
        Ok(data)
    }

    /// Pull a file into memory (v2 `RCV2`), with `flags` as in
    /// [`recv_v2_start`](Self::recv_v2_start): one the device does not
    /// take fails with [`Error::MissingFeature`] or
    /// [`SyncError::InvalidFlags`] before anything is sent.
    pub async fn recv_v2(
        &mut self,
        path: &str,
        flags: SyncFlags,
    ) -> Result<Vec<u8>, Error<S::IoError>> {
        self.recv_v2_start(path, flags).await?;
        let mut data = Vec::new();
        while let Some(chunk) = self.recv_next().await? {
            data.extend_from_slice(chunk);
        }
        Ok(data)
    }

    /// Begin a `SEND` (v1) push.
    ///
    /// `mode` is the mode the device gives the file, e.g.
    /// `FileMode(0o100644)`.
    pub async fn send_start(
        &mut self,
        path: &str,
        mode: FileMode,
    ) -> Result<(), Error<S::IoError>> {
        let mut mode_dec = [0u8; 10];
        let mode_str = format_u32(mode.0, &mut mode_dec);
        self.write_request(SyncId::Send, &[path.as_bytes(), b",", mode_str])
            .await
    }

    /// Begin a `SND2` (v2) push.
    ///
    /// `mode` is as in [`send_start`](Self::send_start). `flags`
    /// combines [`SyncFlags`]; [`SyncFlags::NONE`] pushes uncompressed.
    /// Requires the device to advertise `sendrecv_v2` and the feature of
    /// each flag, failing with [`Error::MissingFeature`] otherwise. adbd
    /// takes one compression flag at most, so two fail with
    /// [`SyncError::InvalidFlags`] whatever the device advertises.
    /// Either way nothing is sent and the session stays usable.
    pub async fn send_v2_start(
        &mut self,
        path: &str,
        mode: FileMode,
        flags: SyncFlags,
    ) -> Result<(), Error<S::IoError>> {
        self.require_sendrecv_v2(flags)?;
        let path_bytes = path.as_bytes();
        // As in `recv_v2_start`, with `sync_send_v2` after the path.
        self.write_message(
            SyncId::Snd2,
            path_bytes.len() as u32,
            &[
                path_bytes,
                &SyncId::Snd2.as_bytes(),
                &mode.0.to_le_bytes(),
                &flags.bits().to_le_bytes(),
            ],
        )
        .await
    }

    /// Send one or more `DATA` chunks.
    ///
    /// `data` is automatically split into [`SYNC_DATA_MAX`]-sized
    /// chunks.  Must be called between a `send*_start` and
    /// [`send_done`](Self::send_done).
    pub async fn send_data(&mut self, data: &[u8]) -> Result<(), Error<S::IoError>> {
        for chunk in data.chunks(SYNC_DATA_MAX) {
            self.write_request(SyncId::Data, &[chunk]).await?;
        }
        Ok(())
    }

    /// Finish a push, providing the file modification time in Unix
    /// seconds: unsigned and 32-bit for v1 and v2 alike, since `DONE`
    /// has no wider field.
    ///
    /// Sends `DONE` and reads the device response (`OKAY` or `FAIL`).
    pub async fn send_done(&mut self, mtime: u32) -> Result<(), Error<S::IoError>> {
        self.write_header(SyncId::Done, mtime).await?;
        self.rx.compact();
        self.read_next_id(&[SyncId::Okay]).await?;
        self.rx.advance(HEADER_SIZE);
        Ok(())
    }

    /// Push a file to the device (v1 `SEND`).
    ///
    /// Convenience wrapper around [`send_start`](Self::send_start) +
    /// [`send_data`](Self::send_data) + [`send_done`](Self::send_done).
    pub async fn send(
        &mut self,
        path: &str,
        mode: FileMode,
        mtime: u32,
        data: &[u8],
    ) -> Result<(), Error<S::IoError>> {
        self.send_start(path, mode).await?;
        self.send_data(data).await?;
        self.send_done(mtime).await
    }

    /// Push a file to the device (v2 `SND2`), with `flags` as in
    /// [`send_v2_start`](Self::send_v2_start): one the device does not
    /// take fails with [`Error::MissingFeature`] or
    /// [`SyncError::InvalidFlags`] before anything is sent.
    pub async fn send_v2(
        &mut self,
        path: &str,
        mode: FileMode,
        mtime: u32,
        flags: SyncFlags,
        data: &[u8],
    ) -> Result<(), Error<S::IoError>> {
        self.send_v2_start(path, mode, flags).await?;
        self.send_data(data).await?;
        self.send_done(mtime).await
    }

    /// Send `QUIT` and close the underlying channel.
    pub async fn quit(mut self) -> Result<(), Error<S::IoError>> {
        self.write_header(SyncId::Quit, 0).await?;
        self.channel.close().await
    }
}

/// Open a `sync:\0` channel and return a [`SyncSession`].
///
/// `buf` is the caller-owned receive buffer — see the
/// [module docs](self) for sizing guidance.
pub async fn open<'a, 'b, S: Session>(
    session: &'a mut S,
    buf: &'b mut [u8],
) -> Result<SyncSession<'a, 'b, S>, Error<S::IoError>> {
    let channel = session.open(b"sync:\0").await?;
    Ok(SyncSession::new(channel, buf))
}
