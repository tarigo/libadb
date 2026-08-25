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
//! [`Error::ReceiveBufferFull`].
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
//! sync.send("/sdcard/upload.txt", 0o100644, 0, b"hello").await?;
//!
//! sync.quit().await?;
//! ```

use alloc::vec::Vec;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use crate::base::channel::Channel;
use crate::base::connection::{
    Connection, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_FEATURES, DEFAULT_MAX_PROPERTIES,
};
use crate::base::error::{Error, SyncError};
use crate::base::recv_buf::RecvBuf;

/// A sync session over an open `sync:\0` channel.
///
/// Provides stat, list, push and pull operations.  Created by [`open`].
/// Multiple operations can be performed on the same session before
/// calling [`quit`](Self::quit).
pub struct SyncSession<
    'a,
    'b,
    T,
    const MAX_CHANNELS: usize = DEFAULT_MAX_CHANNELS,
    const MAX_PROPERTIES: usize = DEFAULT_MAX_PROPERTIES,
    const MAX_FEATURES: usize = DEFAULT_MAX_FEATURES,
> where
    T: Read + Write,
{
    channel: Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
    rx: RecvBuf<'b>,
}

impl<
        'a,
        'b,
        T,
        const MAX_CHANNELS: usize,
        const MAX_PROPERTIES: usize,
        const MAX_FEATURES: usize,
    > SyncSession<'a, 'b, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    /// Wrap an already-opened `sync:\0` channel.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < HEADER_SIZE`.
    pub fn new(
        channel: Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
        buf: &'b mut [u8],
    ) -> Self {
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

    fn peek_id(&self) -> [u8; 4] {
        let mut id = [0u8; 4];
        id.copy_from_slice(&self.rx.buf[self.rx.head..self.rx.head + 4]);
        id
    }

    fn peek_u32(&self, offset: usize) -> u32 {
        u32_at(self.rx.buf, self.rx.head + offset)
    }

    async fn write_header(
        &mut self,
        id: &[u8; 4],
        arg: u32,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let mut hdr = [0u8; HEADER_SIZE];
        hdr[..4].copy_from_slice(id);
        hdr[4..8].copy_from_slice(&arg.to_le_bytes());
        self.channel.write(&hdr).await
    }

    async fn write_request(
        &mut self,
        id: &[u8; 4],
        parts: &[&[u8]],
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let arg_len: usize = parts.iter().map(|p| p.len()).sum();
        let total = HEADER_SIZE + arg_len;

        self.rx.compact();
        let free = self.rx.buf.len() - self.rx.tail;

        if total <= free {
            let s = self.rx.tail;
            self.rx.buf[s..s + 4].copy_from_slice(id);
            self.rx.buf[s + 4..s + 8].copy_from_slice(&(arg_len as u32).to_le_bytes());
            let mut off = s + HEADER_SIZE;
            for p in parts {
                self.rx.buf[off..off + p.len()].copy_from_slice(p);
                off += p.len();
            }
            self.channel.write(&self.rx.buf[s..s + total]).await
        } else {
            self.write_header(id, arg_len as u32).await?;
            for p in parts {
                if !p.is_empty() {
                    self.channel.write(p).await?;
                }
            }
            Ok(())
        }
    }

    async fn read_next_id(
        &mut self,
        allowed: &[[u8; 4]],
    ) -> Result<[u8; 4], Error<<T as ErrorType>::Error>> {
        self.rx
            .fill_at_least(&mut self.channel, HEADER_SIZE)
            .await?;
        let id = self.peek_id();
        if id == ID_FAIL {
            let msg = self.read_fail_body().await?;
            return Err(SyncError::Failed(msg).into());
        }
        if !allowed.contains(&id) {
            return Err(SyncError::UnexpectedId(id).into());
        }
        Ok(id)
    }

    async fn read_fail_body(&mut self) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>> {
        let msg_len = self.peek_u32(4) as usize;
        self.rx.head += HEADER_SIZE;
        if msg_len == 0 {
            return Ok(Vec::new());
        }
        self.rx.fill_at_least(&mut self.channel, msg_len).await?;
        let msg = self.rx.buf[self.rx.head..self.rx.head + msg_len].to_vec();
        self.rx.head += msg_len;
        Ok(msg)
    }

    /// Stat a file (v1).
    ///
    /// Returns zeroed fields when the path does not exist (v1 has no
    /// error code).
    pub async fn stat(&mut self, path: &str) -> Result<StatV1, Error<<T as ErrorType>::Error>> {
        self.rx.compact();
        self.write_request(&ID_STAT, &[path.as_bytes()]).await?;
        self.read_next_id(&[ID_STAT]).await?;

        self.rx
            .fill_at_least(&mut self.channel, STAT_V1_SIZE)
            .await?;
        let mode = self.peek_u32(4);
        let size = self.peek_u32(8);
        let mtime = self.peek_u32(12);
        self.rx.head += STAT_V1_SIZE;
        Ok(StatV1 { mode, size, mtime })
    }

    /// Stat a file (v2).
    ///
    /// Returns full metadata including uid/gid and 64-bit size.
    /// Requires the device to advertise `stat_v2`.
    ///
    /// Returns [`SyncError::RemoteErrno`] when the device reports a
    /// non-zero error code (e.g. `ENOENT`).
    pub async fn stat_v2(&mut self, path: &str) -> Result<StatV2, Error<<T as ErrorType>::Error>> {
        self.rx.compact();
        self.write_request(&ID_STA2, &[path.as_bytes()]).await?;
        self.read_next_id(&[ID_STA2]).await?;

        self.rx
            .fill_at_least(&mut self.channel, STAT_V2_SIZE)
            .await?;
        let body = &self.rx.buf[self.rx.head + 4..self.rx.head + STAT_V2_SIZE];
        let stat = parse_stat_v2_body(body.try_into().expect("checked STAT_V2_SIZE bytes"));
        self.rx.head += STAT_V2_SIZE;

        if stat.error != 0 {
            return Err(SyncError::RemoteErrno(stat.error).into());
        }
        Ok(stat)
    }

    /// List a directory (v1).
    pub async fn list(
        &mut self,
        path: &str,
    ) -> Result<Vec<DirEntry>, Error<<T as ErrorType>::Error>> {
        self.rx.compact();
        self.write_request(&ID_LIST, &[path.as_bytes()]).await?;

        let mut entries = Vec::new();
        loop {
            if self.read_next_id(&[ID_DENT, ID_DONE]).await? == ID_DONE {
                // adbd closes a listing with a whole `dent` record whose
                // id is DONE, not a bare header — consuming only the
                // head would leave its tail in the stream.
                self.rx
                    .fill_at_least(&mut self.channel, DENT_V1_SIZE)
                    .await?;
                self.rx.head += DENT_V1_SIZE;
                return Ok(entries);
            }

            self.rx
                .fill_at_least(&mut self.channel, DENT_V1_SIZE)
                .await?;
            let mode = self.peek_u32(4);
            let size = self.peek_u32(8);
            let mtime = self.peek_u32(12);
            let namelen = self.peek_u32(16) as usize;
            self.rx.head += DENT_V1_SIZE;

            self.rx.fill_at_least(&mut self.channel, namelen).await?;
            let name = self.rx.buf[self.rx.head..self.rx.head + namelen].to_vec();
            self.rx.head += namelen;

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
    /// Requires the device to advertise `ls_v2`.  Entries whose stat
    /// failed on the device have a non-zero `stat.error` field but are
    /// still included in the result.
    pub async fn list_v2(
        &mut self,
        path: &str,
    ) -> Result<Vec<DirEntryV2>, Error<<T as ErrorType>::Error>> {
        self.rx.compact();
        self.write_request(&ID_LIS2, &[path.as_bytes()]).await?;

        let mut entries = Vec::new();
        loop {
            if self.read_next_id(&[ID_DNT2, ID_DONE]).await? == ID_DONE {
                // Same as `list`, with the v2 record size.
                self.rx
                    .fill_at_least(&mut self.channel, DENT_V2_SIZE)
                    .await?;
                self.rx.head += DENT_V2_SIZE;
                return Ok(entries);
            }

            self.rx
                .fill_at_least(&mut self.channel, DENT_V2_SIZE)
                .await?;
            let body = &self.rx.buf[self.rx.head + 4..self.rx.head + STAT_V2_SIZE];
            let stat = parse_stat_v2_body(body.try_into().expect("checked STAT_V2_SIZE bytes"));
            let namelen = self.peek_u32(72) as usize;
            self.rx.head += DENT_V2_SIZE;

            self.rx.fill_at_least(&mut self.channel, namelen).await?;
            let name = self.rx.buf[self.rx.head..self.rx.head + namelen].to_vec();
            self.rx.head += namelen;

            entries.push(DirEntryV2 { name, stat });
        }
    }

    /// Begin a `RECV` (v1) pull.
    pub async fn recv_start(&mut self, path: &str) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.rx.compact();
        self.write_request(&ID_RECV, &[path.as_bytes()]).await
    }

    /// Begin a `RCV2` (v2) pull.
    ///
    /// `flags` is a combination of [`flags`] constants.  Pass
    /// [`flags::NONE`] for uncompressed transfer.
    pub async fn recv_v2_start(
        &mut self,
        path: &str,
        flags: u32,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let path_bytes = path.as_bytes();
        self.rx.compact();
        self.write_header(&ID_RCV2, path_bytes.len() as u32).await?;
        self.channel.write(path_bytes).await?;
        self.channel.write(&flags.to_le_bytes()).await?;
        Ok(())
    }

    /// Read the next `DATA` chunk from an in-progress recv.
    ///
    /// Returns `Ok(Some(data))` for each chunk and `Ok(None)` when the
    /// device signals `DONE`.  The returned slice references the
    /// internal buffer and is valid until the next method call.
    ///
    /// Must be called after [`recv_start`](Self::recv_start) or
    /// [`recv_v2_start`](Self::recv_v2_start).
    pub async fn recv_next(&mut self) -> Result<Option<&[u8]>, Error<<T as ErrorType>::Error>> {
        self.rx.compact();
        if self.read_next_id(&[ID_DATA, ID_DONE]).await? == ID_DONE {
            self.rx.head += HEADER_SIZE;
            return Ok(None);
        }

        let data_len = self.peek_u32(4) as usize;
        let total = HEADER_SIZE + data_len;
        if total > self.rx.buf.len() {
            return Err(Error::ReceiveBufferFull);
        }
        self.rx.fill_at_least(&mut self.channel, total).await?;

        let data_start = self.rx.head + HEADER_SIZE;
        let data_end = data_start + data_len;
        self.rx.head = data_end;
        Ok(Some(&self.rx.buf[data_start..data_end]))
    }

    /// Pull a file into memory (v1 `RECV`).
    ///
    /// Convenience wrapper around [`recv_start`](Self::recv_start) +
    /// [`recv_next`](Self::recv_next).  For large files prefer the
    /// streaming API.
    pub async fn recv(&mut self, path: &str) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>> {
        self.recv_start(path).await?;
        let mut data = Vec::new();
        while let Some(chunk) = self.recv_next().await? {
            data.extend_from_slice(chunk);
        }
        Ok(data)
    }

    /// Pull a file into memory (v2 `RCV2`).
    pub async fn recv_v2(
        &mut self,
        path: &str,
        flags: u32,
    ) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>> {
        self.recv_v2_start(path, flags).await?;
        let mut data = Vec::new();
        while let Some(chunk) = self.recv_next().await? {
            data.extend_from_slice(chunk);
        }
        Ok(data)
    }

    /// Begin a `SEND` (v1) push.
    ///
    /// `mode` is the Unix file permission bits (e.g. `0o100644`).
    pub async fn send_start(
        &mut self,
        path: &str,
        mode: u32,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let mut mode_dec = [0u8; 10];
        let mode_str = format_u32(mode, &mut mode_dec);
        self.write_request(&ID_SEND, &[path.as_bytes(), b",", mode_str])
            .await
    }

    /// Begin a `SND2` (v2) push.
    ///
    /// `flags` is a combination of [`flags`] constants.
    pub async fn send_v2_start(
        &mut self,
        path: &str,
        mode: u32,
        flags: u32,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let path_bytes = path.as_bytes();
        self.rx.compact();
        self.write_header(&ID_SND2, path_bytes.len() as u32).await?;
        self.channel.write(path_bytes).await?;
        let mut info = [0u8; 8];
        info[0..4].copy_from_slice(&mode.to_le_bytes());
        info[4..8].copy_from_slice(&flags.to_le_bytes());
        self.channel.write(&info).await?;
        Ok(())
    }

    /// Send one or more `DATA` chunks.
    ///
    /// `data` is automatically split into [`SYNC_DATA_MAX`]-sized
    /// chunks.  Must be called between a `send*_start` and
    /// [`send_done`](Self::send_done).
    pub async fn send_data(&mut self, data: &[u8]) -> Result<(), Error<<T as ErrorType>::Error>> {
        for chunk in data.chunks(SYNC_DATA_MAX) {
            self.write_request(&ID_DATA, &[chunk]).await?;
        }
        Ok(())
    }

    /// Finish a push, providing the file modification time (Unix
    /// seconds).
    ///
    /// Sends `DONE` and reads the device response (`OKAY` or `FAIL`).
    pub async fn send_done(&mut self, mtime: u32) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.write_header(&ID_DONE, mtime).await?;
        self.rx.compact();
        self.read_next_id(&[ID_OKAY]).await?;
        self.rx.head += HEADER_SIZE;
        Ok(())
    }

    /// Push a file to the device (v1 `SEND`).
    ///
    /// Convenience wrapper around [`send_start`](Self::send_start) +
    /// [`send_data`](Self::send_data) + [`send_done`](Self::send_done).
    pub async fn send(
        &mut self,
        path: &str,
        mode: u32,
        mtime: u32,
        data: &[u8],
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.send_start(path, mode).await?;
        self.send_data(data).await?;
        self.send_done(mtime).await
    }

    /// Push a file to the device (v2 `SND2`).
    pub async fn send_v2(
        &mut self,
        path: &str,
        mode: u32,
        mtime: u32,
        flags: u32,
        data: &[u8],
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.send_v2_start(path, mode, flags).await?;
        self.send_data(data).await?;
        self.send_done(mtime).await
    }

    /// Send `QUIT` and close the underlying channel.
    pub async fn quit(mut self) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.write_header(&ID_QUIT, 0).await?;
        self.channel.close().await
    }
}

/// Open a `sync:\0` channel and return a [`SyncSession`].
///
/// `buf` is the caller-owned receive buffer — see the
/// [module docs](self) for sizing guidance.
pub async fn open<'a, 'b, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    buf: &'b mut [u8],
) -> Result<SyncSession<'a, 'b, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let channel = conn.open(b"sync:\0").await?;
    Ok(SyncSession::new(channel, buf))
}

mod format;
pub use format::*;
use format::{
    u32_at, DENT_V1_SIZE, DENT_V2_SIZE, ID_DATA, ID_DENT, ID_DNT2, ID_DONE, ID_FAIL, ID_LIS2,
    ID_LIST, ID_OKAY, ID_QUIT, ID_RCV2, ID_RECV, ID_SEND, ID_SND2, ID_STA2, ID_STAT, STAT_V1_SIZE,
};

#[cfg(test)]
mod tests;
