//! Logcat — stream and parse Android log entries.
//!
//! Runs `logcat` on the device via a `shell,v2` channel.  Two main
//! operating modes:
//!
//! * **Binary** — [`open`] / [`dump`] append the `-B` flag so `logcat`
//!   emits raw `logger_entry` records, then parse them into typed
//!   [`LogEntry`] values.
//! * **Text** — [`open_text`] / [`exec_text`] pass your arguments
//!   verbatim and return a raw [`Shell`] or [`CommandOutput`].
//!
//! # Wire format (binary mode)
//!
//! Each binary entry is a `logger_entry` header followed by a payload.
//! The header format (v4, 28 bytes):
//!
//! ```text
//! u16  payload_len
//! u16  hdr_size      (≥ 24; typically 28 for v4)
//! i32  pid
//! u32  tid
//! i32  sec           (seconds since epoch)
//! i32  nsec
//! u32  lid           (log buffer id)
//! u32  uid           (v4 only, present when hdr_size ≥ 28)
//! ```
//!
//! For main / system / radio / crash / kernel buffers the payload is:
//!
//! ```text
//! [priority: u8] [tag \0] [message …]
//! ```
//!
//! For events / stats / security buffers the payload is raw binary
//! event data — [`LogEntry::tag`] will be empty and
//! [`LogEntry::message`] will contain the entire payload.
//!
//! # Examples
//!
//! ```ignore
//! // Stream parsed binary entries from main + system buffers:
//! let mut rx = [0u8; 64 * 1024];
//! let mut logcat = logcat::open(&mut conn, &["-b", "main,system"], &mut rx).await?;
//! loop {
//!     let entry = logcat.read_entry().await?;
//!     println!("{} {}/{}: {}",
//!         entry.pid, entry.priority, entry.tag_lossy(), entry.message_lossy());
//! }
//!
//! // Dump last 100 crash-buffer entries:
//! let entries = logcat::dump(&mut conn, &["-b", "crash", "-t", "100"], &mut rx).await?;
//!
//! // Text mode (thin wrapper over shell_v2):
//! let output = logcat::exec_text(&mut conn, &["-d", "-v", "threadtime"], &mut rx).await?;
//! ```

use alloc::vec::Vec;

use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use crate::base::channel::Channel;
use crate::base::connection::Connection;
use crate::base::error::Error;
use crate::shell::v2::{self as shell_v2, CommandOutput, Shell};

/// A live `logcat -B` streaming session.
///
/// Wraps an ADB channel running `logcat -B …` and decodes the
/// `shell_v2` framing + binary log format directly in the caller-owned
/// buffer — no intermediate heap allocations on the read path (only
/// the returned [`LogEntry`] itself allocates for `tag` and `message`).
///
/// The buffer is split into two logical regions:
///
/// ```text
/// buf: [accumulated stdout][ gap ][raw channel data][ free ]
///       0          acc_end        head         tail     len
/// ```
///
/// STDOUT payloads are absorbed into the accumulation zone by shifting
/// them over the 5-byte `shell_v2` header.  Non-STDOUT frames (stderr,
/// exit) are skipped in-place.
pub struct Logcat<
    'a,
    'b,
    T,
    const MAX_CHANNELS: usize = { crate::base::connection::DEFAULT_MAX_CHANNELS },
    const MAX_PROPERTIES: usize = { crate::base::connection::DEFAULT_MAX_PROPERTIES },
    const MAX_FEATURES: usize = { crate::base::connection::DEFAULT_MAX_FEATURES },
> where
    T: Read + Write,
{
    channel: Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
    buf: &'b mut [u8],
    acc_end: usize,
    head: usize,
    tail: usize,
}

impl<
        'a,
        'b,
        T,
        const MAX_CHANNELS: usize,
        const MAX_PROPERTIES: usize,
        const MAX_FEATURES: usize,
    > Logcat<'a, 'b, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    fn new(
        channel: Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
        buf: &'b mut [u8],
    ) -> Self {
        assert!(
            buf.len() >= shell_v2::HEADER_SIZE,
            "Logcat buffer must be at least {} bytes",
            shell_v2::HEADER_SIZE,
        );
        Self {
            channel,
            buf,
            acc_end: 0,
            head: 0,
            tail: 0,
        }
    }

    fn compact_raw(&mut self) {
        if self.acc_end < self.head {
            self.buf.copy_within(self.head..self.tail, self.acc_end);
            self.tail -= self.head - self.acc_end;
            self.head = self.acc_end;
        }
    }

    async fn fill_raw(&mut self, n: usize) -> Result<(), Error<<T as ErrorType>::Error>> {
        while self.tail - self.head < n {
            if self.tail >= self.buf.len() {
                self.compact_raw();
                if self.tail >= self.buf.len() {
                    return Err(Error::ReceiveBufferFull);
                }
            }
            let read = self.channel.read(&mut self.buf[self.tail..]).await?;
            self.tail += read;
        }
        Ok(())
    }

    fn absorb_stdout(&mut self, payload_len: usize) {
        self.compact_raw();
        let payload_start = self.head + shell_v2::HEADER_SIZE;
        let payload_end = payload_start + payload_len;
        self.buf.copy_within(payload_start..payload_end, self.head);
        self.acc_end = self.head + payload_len;
        self.head = payload_end;
    }

    /// Read the next parsed binary log entry.
    ///
    /// Blocks until a complete `logger_entry` has been received and
    /// decoded.  Returns [`Error::ChannelClosed`] when the logcat
    /// process exits and all buffered data has been consumed.
    ///
    /// The only heap allocations are the `tag` and `message` fields
    /// inside the returned [`LogEntry`].
    pub async fn read_entry(&mut self) -> Result<LogEntry, Error<<T as ErrorType>::Error>> {
        loop {
            if let Some((entry, consumed)) =
                parse_entry(&self.buf[..self.acc_end]).map_err(Error::Logcat)?
            {
                self.buf.copy_within(consumed..self.acc_end, 0);
                self.acc_end -= consumed;
                return Ok(entry);
            }

            loop {
                match self.fill_raw(shell_v2::HEADER_SIZE).await {
                    Ok(()) => {}
                    Err(Error::ChannelClosed) => return self.drain_acc_or_close(),
                    Err(e) => return Err(e),
                }

                let hdr: [u8; shell_v2::HEADER_SIZE] = self.buf
                    [self.head..self.head + shell_v2::HEADER_SIZE]
                    .try_into()
                    .unwrap();
                let (id, payload_len) = shell_v2::parse_header(&hdr);
                let frame_size = shell_v2::HEADER_SIZE + payload_len as usize;

                match self.fill_raw(frame_size).await {
                    Ok(()) => {}
                    Err(Error::ChannelClosed) => return self.drain_acc_or_close(),
                    Err(e) => return Err(e),
                }

                match id {
                    shell_v2::STDOUT => {
                        self.absorb_stdout(payload_len as usize);
                        break;
                    }
                    shell_v2::EXIT => return self.drain_acc_or_close(),
                    _ => self.head += frame_size,
                }
            }
        }
    }

    fn drain_acc_or_close(&mut self) -> Result<LogEntry, Error<<T as ErrorType>::Error>> {
        if let Some((entry, consumed)) =
            parse_entry(&self.buf[..self.acc_end]).map_err(Error::Logcat)?
        {
            self.buf.copy_within(consumed..self.acc_end, 0);
            self.acc_end -= consumed;
            return Ok(entry);
        }
        Err(Error::ChannelClosed)
    }

    /// Close the underlying channel.
    pub async fn close(self) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.channel.close().await
    }
}

fn write_destination(buf: &mut [u8], prefix: &[u8], args: &[&str]) -> Option<usize> {
    crate::base::destination::write_destination(buf, &[b"shell,v2,raw:", prefix], args)
}

async fn open_shell_channel<'a, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    prefix: &[u8],
    args: &[&str],
    buf: &mut [u8],
) -> Result<Channel<'a, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    conn.require_feature(crate::base::protocol::features::Feature::ShellV2)?;
    let dest_len = write_destination(buf, prefix, args).ok_or(Error::ReceiveBufferFull)?;
    conn.open(&buf[..dest_len]).await
}

/// Open a streaming `logcat -B` session, returning a [`Logcat`] that
/// yields parsed [`LogEntry`] values.
///
/// `args` are extra arguments forwarded to `logcat` **after** the
/// implicit `-B` flag.  Common choices:
///
/// * `&["-b", "main,system"]` — limit to specific buffers
/// * `&["-s", "MyTag:D"]` — filter by tag / priority
/// * `&["--pid=1234"]` — filter by PID
/// * `&["-T", "100"]` — start from the last 100 entries, then stream
///
/// `buf` is the caller-owned buffer used both for channel IO and for
/// accumulating binary stdout data.  A few KiB is enough for typical
/// use; increase for high-throughput streams.
pub async fn open<'a, 'b, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    args: &[&str],
    buf: &'b mut [u8],
) -> Result<Logcat<'a, 'b, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let channel = open_shell_channel(conn, b"logcat -B", args, buf).await?;
    Ok(Logcat::new(channel, buf))
}

/// Dump all binary log entries and return them.
///
/// Equivalent to `logcat -B -d <args>` — the `-d` flag causes logcat
/// to print the current log contents and exit instead of streaming.
///
/// `args` and `buf` have the same meaning as in [`open`].
pub async fn dump<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    args: &[&str],
    buf: &mut [u8],
) -> Result<Vec<LogEntry>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let channel = open_shell_channel(conn, b"logcat -B -d", args, buf).await?;
    let mut logcat = Logcat::new(channel, buf);

    let mut entries = Vec::new();
    loop {
        match logcat.read_entry().await {
            Ok(entry) => entries.push(entry),
            Err(Error::ChannelClosed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(entries)
}

/// Open a `logcat` text stream, returning a [`Shell`] wrapper.
///
/// Arguments are passed verbatim — no `-B` is added.  Use this when
/// you want the human-readable text output or need a format flag like
/// `-v threadtime`.
///
/// For a one-shot dump pass `"-d"` in `args`; otherwise logcat streams
/// indefinitely.
pub async fn open_text<'a, 'b, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    args: &[&str],
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let channel = open_shell_channel(conn, b"logcat", args, rx).await?;
    Ok(Shell::new(channel, rx))
}

/// Run a one-shot text logcat, collecting stdout and stderr.
///
/// Arguments are passed verbatim.  You almost always want to include
/// `"-d"` (dump and exit) or `"-t"` / `"-T"` (last N entries) so that
/// `logcat` terminates on its own; without one of these flags it will
/// stream indefinitely and this function will never return.
pub async fn exec_text<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    args: &[&str],
    rx: &mut [u8],
) -> Result<CommandOutput, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let channel = open_shell_channel(conn, b"logcat", args, rx).await?;
    let mut shell = Shell::new(channel, rx);
    shell.close_stdin().await?;
    shell.collect().await
}

mod format;
pub use format::*;

#[cfg(test)]
mod tests;
