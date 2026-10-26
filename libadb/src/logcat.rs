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

use crate::base::channel::Channel;
use crate::base::error::{Error, ProtocolError};
use crate::base::session::Session;
use crate::shell::v2::{self as shell_v2, CommandOutput, Shell};

/// A live `logcat -B` streaming session.
///
/// Wraps an ADB channel running `logcat -B …` and decodes the
/// `shell_v2` framing + binary log format directly in the caller-owned
/// buffer — no intermediate heap allocations on the read path (only
/// the returned [`LogEntry`] itself allocates for `tag` and `message`).
pub struct Logcat<'a, 'b, S> {
    channel: Channel<'a, S>,
    buf: &'b mut [u8],
    // buf[acc_start..acc_end] is stdout not yet parsed into entries and
    // buf[head..tail] raw input not yet looked at. acc_end <= head, so
    // stdout moved down to acc_end never overwrites unread input.
    acc_start: usize,
    acc_end: usize,
    head: usize,
    tail: usize,
    frame_id: u8,
    frame_left: usize,
    exit_code: Option<u8>,
}

impl<'a, 'b, S: Session> Logcat<'a, 'b, S> {
    fn new(channel: Channel<'a, S>, buf: &'b mut [u8]) -> Self {
        assert!(
            buf.len() >= shell_v2::HEADER_SIZE,
            "Logcat buffer must be at least {} bytes",
            shell_v2::HEADER_SIZE,
        );
        Self {
            channel,
            buf,
            acc_start: 0,
            acc_end: 0,
            head: 0,
            tail: 0,
            frame_id: 0,
            frame_left: 0,
            exit_code: None,
        }
    }

    fn compact(&mut self) {
        // Accumulator first: where the raw bytes go may overlap where it is now.
        if self.acc_start > 0 {
            shift(self.buf, self.acc_start..self.acc_end, 0);
            self.acc_end -= self.acc_start;
            self.acc_start = 0;
        }
        if self.acc_end < self.head {
            shift(self.buf, self.head..self.tail, self.acc_end);
            self.tail -= self.head - self.acc_end;
            self.head = self.acc_end;
        }
    }

    async fn fill(&mut self) -> Result<(), Error<S::IoError>> {
        if self.tail == self.buf.len() {
            self.compact();
            if self.tail == self.buf.len() {
                return Err(Error::ReceiveBufferFull);
            }
        }
        let read = self.channel.read(&mut self.buf[self.tail..]).await?;
        self.tail += read;
        Ok(())
    }

    /// Read the next parsed binary log entry.
    ///
    /// Blocks until a complete `logger_entry` has been received and
    /// decoded.  Once logcat has exited and every entry before that has
    /// been returned, fails with [`Error::ChannelClosed`] if it exited
    /// with status 0 and with [`LogcatError::Exited`] otherwise, and goes
    /// on doing so.  Returns [`Error::ReceiveBufferFull`] when an entry
    /// is too long for the buffer passed to [`open`].
    ///
    /// The only heap allocations are the `tag` and `message` fields
    /// inside the returned [`LogEntry`].
    pub async fn read_entry(&mut self) -> Result<LogEntry, Error<S::IoError>> {
        loop {
            if let Some(entry) = self.take_entry()? {
                return Ok(entry);
            }
            match self.exit_code {
                Some(0) => return Err(Error::ChannelClosed),
                Some(code) => return Err(LogcatError::Exited { code }.into()),
                None => {}
            }
            if self.frame_left > 0 && self.head < self.tail {
                if self.frame_id == shell_v2::EXIT {
                    self.exit_code = Some(self.buf[self.head]);
                    continue;
                }
                let n = self.frame_left.min(self.tail - self.head);
                if self.frame_id == shell_v2::STDOUT {
                    if self.acc_start == self.acc_end {
                        self.acc_start = self.head;
                        self.acc_end = self.head;
                    } else if self.acc_end < self.head {
                        shift(self.buf, self.head..self.head + n, self.acc_end);
                    }
                    self.acc_end += n;
                }
                self.head += n;
                self.frame_left -= n;
                continue;
            }
            if self.frame_left == 0 && self.tail - self.head >= shell_v2::HEADER_SIZE {
                let hdr: [u8; shell_v2::HEADER_SIZE] = self.buf
                    [self.head..self.head + shell_v2::HEADER_SIZE]
                    .try_into()
                    .unwrap();
                let (id, len) = shell_v2::parse_header(&hdr);
                match id {
                    shell_v2::EXIT if len == 0 => {
                        return Err(ProtocolError::ShortExitPayload.into())
                    }
                    shell_v2::STDOUT | shell_v2::STDERR | shell_v2::EXIT => {}
                    other => return Err(ProtocolError::UnexpectedShellFrame(other).into()),
                }
                self.head += shell_v2::HEADER_SIZE;
                self.frame_id = id;
                self.frame_left = len as usize;
                continue;
            }
            match self.fill().await {
                Ok(()) => {}
                Err(Error::ChannelClosed) => return self.drain_acc_or_close(),
                Err(e) => return Err(e),
            }
        }
    }

    fn take_entry(&mut self) -> Result<Option<LogEntry>, Error<S::IoError>> {
        let Some((entry, consumed)) =
            parse_entry(&self.buf[self.acc_start..self.acc_end]).map_err(Error::Logcat)?
        else {
            return Ok(None);
        };
        self.acc_start += consumed;
        Ok(Some(entry))
    }

    fn drain_acc_or_close(&mut self) -> Result<LogEntry, Error<S::IoError>> {
        self.take_entry()?.ok_or(Error::ChannelClosed)
    }

    /// Close the underlying channel.
    pub async fn close(self) -> Result<(), Error<S::IoError>> {
        self.channel.close().await
    }
}

fn shift(buf: &mut [u8], from: core::ops::Range<usize>, to: usize) {
    #[cfg(test)]
    tests::MOVED.with(|moved| moved.set(moved.get() + from.len()));
    buf.copy_within(from, to);
}

fn write_destination(
    buf: &mut [u8],
    prefix: &[u8],
    args: &[&str],
) -> Result<usize, crate::base::destination::DestinationError> {
    crate::base::destination::write_destination(buf, &[b"shell,v2,raw:", prefix], args)
}

async fn open_shell_channel<'a, S: Session>(
    session: &'a mut S,
    prefix: &[u8],
    args: &[&str],
    buf: &mut [u8],
) -> Result<Channel<'a, S>, Error<S::IoError>> {
    session.require_feature(crate::base::protocol::features::Feature::ShellV2)?;
    let dest_len = write_destination(buf, prefix, args)?;
    session.open(&buf[..dest_len]).await
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
/// Each element is one argument to `logcat`, so a filter expression may
/// hold spaces or shell metacharacters without being split or executed.
///
/// `buf` is the caller-owned buffer used both for channel IO and for
/// accumulating binary stdout data.  It must be at least 4 bytes longer
/// than the longest entry, and logcat writes none longer than 5 KiB
/// (`LOGGER_ENTRY_MAX_LEN`), so 5 KiB + 4 bytes is always enough for the
/// entries; a larger buffer only means fewer reads.  Opening first
/// builds the `shell,v2,raw:logcat -B …` destination in it, so very long
/// `args` need room there too, or this fails with
/// [`Error::ReceiveBufferFull`].
pub async fn open<'a, 'b, S: Session>(
    session: &'a mut S,
    args: &[&str],
    buf: &'b mut [u8],
) -> Result<Logcat<'a, 'b, S>, Error<S::IoError>> {
    let channel = open_shell_channel(session, b"logcat -B", args, buf).await?;
    Ok(Logcat::new(channel, buf))
}

/// Dump all binary log entries and return them.
///
/// Equivalent to `logcat -B -d <args>` — the `-d` flag causes logcat
/// to print the current log contents and exit instead of streaming.
/// Fails with [`LogcatError::Exited`] when logcat exits with a non-zero
/// status, as it does for an unknown buffer.  A failure drops the
/// entries read before it; to keep them, read the stream through
/// [`open`] and [`Logcat::read_entry`].
///
/// `args` and `buf` have the same meaning as in [`open`].
pub async fn dump<S: Session>(
    session: &mut S,
    args: &[&str],
    buf: &mut [u8],
) -> Result<Vec<LogEntry>, Error<S::IoError>> {
    let channel = open_shell_channel(session, b"logcat -B -d", args, buf).await?;
    let mut logcat = Logcat::new(channel, buf);

    let mut entries = Vec::new();
    let end = loop {
        match logcat.read_entry().await {
            Ok(entry) => entries.push(entry),
            Err(Error::ChannelClosed) => break Ok(entries),
            Err(e) => break Err(e),
        }
    };
    // The device's CLSE only marks the slot closed; ours frees it.
    let _ = logcat.close().await;
    end
}

/// Open a `logcat` text stream, returning a [`Shell`] wrapper.
///
/// Arguments are passed verbatim — no `-B` is added.  Use this when
/// you want the human-readable text output or need a format flag like
/// `-v threadtime`.
///
/// For a one-shot dump pass `"-d"` in `args`; otherwise logcat streams
/// indefinitely.
pub async fn open_text<'a, 'b, S: Session>(
    session: &'a mut S,
    args: &[&str],
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, S>, Error<S::IoError>> {
    let channel = open_shell_channel(session, b"logcat", args, rx).await?;
    Ok(Shell::new(channel, rx))
}

/// Run a one-shot text logcat, collecting stdout and stderr.
///
/// Arguments are passed verbatim.  You almost always want to include
/// `"-d"` (dump and exit) or `"-t"` / `"-T"` (last N entries) so that
/// `logcat` terminates on its own; without one of these flags it will
/// stream indefinitely and this function will never return.
pub async fn exec_text<S: Session>(
    session: &mut S,
    args: &[&str],
    rx: &mut [u8],
) -> Result<CommandOutput, Error<S::IoError>> {
    let channel = open_shell_channel(session, b"logcat", args, rx).await?;
    let mut shell = Shell::new(channel, rx);
    shell.close_stdin().await?;
    shell.collect().await
}

mod format;
pub use format::*;

#[cfg(test)]
mod tests;
