//! Shell v2 protocol on top of an ADB channel.
//!
//! ADB exposes two shell protocols:
//!
//! * `shell:` — legacy, interleaves stdout and stderr in a single byte
//!   stream and provides no exit code.
//! * `shell,v2,...:` — frames stdout, stderr, exit code, stdin and
//!   window-resize events as `[id: u8, len: u32 LE, payload]` packets,
//!   so the host can tell the streams apart and learn the exit status.
//!
//! This module wraps an open [`Channel`] and handles framing. For
//! one-shot command execution use [`exec`]; for an interactive session
//! (PTY, stdin forwarding, resize) use [`open_interactive`] which
//! allocates a PTY on the device, sets `TERM` and the initial window
//! size, and returns a [`Shell`] ready for full-duplex use with
//! [`Shell::pump`] / [`Shell::try_next_frame`].

use alloc::vec::Vec;
use core::future::Future;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use crate::base::channel::{Channel, SelectResult};
use crate::base::connection::{
    Connection, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_FEATURES, DEFAULT_MAX_PROPERTIES,
};
use crate::base::destination::build_shell_v2_destination;
use crate::base::error::{Error, ProtocolError};
use crate::base::protocol::features::Feature;

/// Stdin payload from host to device.
pub const STDIN: u8 = 0;
/// Stdout payload from device to host.
pub const STDOUT: u8 = 1;
/// Stderr payload from device to host.
pub const STDERR: u8 = 2;
/// Exit code (1-byte payload) from device to host.
pub const EXIT: u8 = 3;
/// Host signals that no more stdin will be sent.
pub const CLOSE_STDIN: u8 = 4;
/// Host notifies device of a terminal resize.
pub const WINDOW_SIZE_CHANGE: u8 = 5;

/// Size of the framing header in bytes.
pub const HEADER_SIZE: usize = 5;

pub(crate) fn parse_header(buf: &[u8; HEADER_SIZE]) -> (u8, u32) {
    let id = buf[0];
    let length = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    (id, length)
}

pub(crate) fn encode_window_size(rows: u16, cols: u16) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&rows.to_le_bytes());
    buf[2..4].copy_from_slice(&cols.to_le_bytes());
    buf
}

/// A decoded shell_v2 frame produced by [`Shell::read_frame`] /
/// [`Shell::try_next_frame`].
#[derive(Debug, Clone)]
pub enum Frame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// `EXIT` payload — the device process exit code.
    Exit(u8),
    /// Frame with an unrecognized id; the raw payload is returned as-is.
    Other {
        id: u8,
        payload: Vec<u8>,
    },
}

/// Result of running a command to completion.
#[derive(Debug, Clone, Default)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: u8,
}

/// Shell_v2 wrapper around an open [`Channel`].
///
/// Provides framing, helpers for the well-known frame types, and a
/// [`pump`](Self::pump) method that integrates with [`Channel::select`]
/// for full-duplex interactive sessions.
///
/// `Shell` does not own its receive buffer — the caller supplies a
/// single fixed-size byte slice in [`new`](Self::new) that serves both
/// as the destination of every channel read and as the framing
/// accumulator. The wrapper performs zero heap allocation; the only
/// per-frame allocation is the [`Vec<u8>`] held inside each [`Frame`]
/// variant returned to the caller.
///
/// The slice is used as a linear ring: unread bytes occupy
/// `rx[head..tail]`, fresh bytes are appended at `tail`, and the data
/// is compacted to the start of `rx` whenever the tail hits the end.
/// If after compaction there is still no free space — i.e. the buffer
/// is fully occupied with one in-progress frame — operations return
/// [`Error::ReceiveBufferFull`]. Frames whose payload exceeds the
/// buffer size are delivered in multiple chunks transparently.
pub struct Shell<
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
    rx: &'b mut [u8],
    decoder: FrameDecoder,
}

impl<
        'a,
        'b,
        T,
        const MAX_CHANNELS: usize,
        const MAX_PROPERTIES: usize,
        const MAX_FEATURES: usize,
    > Shell<'a, 'b, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    /// Wrap an already-opened channel.
    ///
    /// The channel must have been opened against a `shell,v2,...`
    /// destination. `rx` is the caller-owned receive buffer used for
    /// channel reads and framing. Frames whose payload fits in the
    /// buffer are returned as a single [`Frame`]; larger payloads are
    /// delivered as multiple consecutive chunks transparently.
    ///
    /// # Panics
    ///
    /// Panics if `rx.len() < HEADER_SIZE`. A buffer smaller than the
    /// 5-byte header cannot decode any frame at all and would only be
    /// able to surface a [`ReceiveBufferFull`](Error::ReceiveBufferFull)
    /// error — turning that into a loud failure at construction time
    /// is friendlier than at the first read.
    pub fn new(
        channel: Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
        rx: &'b mut [u8],
    ) -> Self {
        assert!(
            rx.len() >= HEADER_SIZE,
            "Shell rx buffer must be at least HEADER_SIZE ({}) bytes",
            HEADER_SIZE,
        );
        Self {
            channel,
            rx,
            decoder: FrameDecoder::new(),
        }
    }

    /// Send a raw frame `[id, len, payload]` over the channel.
    ///
    /// When possible the frame is assembled in the free tail of the
    /// caller-owned `rx` buffer so no heap allocation is required.
    /// If the frame is too large for the remaining space, header and
    /// payload are written as two separate channel writes (still
    /// zero-alloc — shell_v2 is stream-oriented so the receiver
    /// reassembles from the byte stream regardless of WRTE boundaries).
    pub async fn send_frame(
        &mut self,
        id: u8,
        payload: &[u8],
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let len_u32 = u32::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge)?;
        let hdr: [u8; HEADER_SIZE] = {
            let b = len_u32.to_le_bytes();
            [id, b[0], b[1], b[2], b[3]]
        };
        let total = HEADER_SIZE + payload.len();

        self.decoder.compact(self.rx);
        let free = self.rx.len() - self.decoder.tail;

        if total <= free {
            let start = self.decoder.tail;
            self.rx[start..start + HEADER_SIZE].copy_from_slice(&hdr);
            self.rx[start + HEADER_SIZE..start + total].copy_from_slice(payload);
            self.channel.write(&self.rx[start..start + total]).await
        } else {
            self.channel.write(&hdr).await?;
            if !payload.is_empty() {
                self.channel.write(payload).await?;
            }
            Ok(())
        }
    }

    /// Send a `STDIN` frame.
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.send_frame(STDIN, data).await
    }

    /// Send a `CLOSE_STDIN` frame, telling the device that no further
    /// stdin will be written.
    pub async fn close_stdin(&mut self) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.send_frame(CLOSE_STDIN, &[]).await
    }

    /// Send a `WINDOW_SIZE_CHANGE` frame.
    pub async fn set_window_size(
        &mut self,
        rows: u16,
        cols: u16,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let payload = encode_window_size(rows, cols);
        self.send_frame(WINDOW_SIZE_CHANGE, &payload).await
    }

    /// Read the next decoded frame, blocking until one is available.
    ///
    /// `Ok(0)` from the channel is treated as "no new bytes this round"
    /// (e.g. an empty WRTE payload) and the loop simply waits for more.
    /// End-of-stream is reported by the channel as
    /// [`Error::ChannelClosed`], not as a zero-length read.
    ///
    /// Returns [`Error::ReceiveBufferFull`] if the caller-provided
    /// receive buffer cannot fit the frame currently being assembled.
    pub async fn read_frame(&mut self) -> Result<Frame, Error<<T as ErrorType>::Error>> {
        loop {
            if let Some(frame) = self.try_next_frame()? {
                return Ok(frame);
            }
            self.ensure_writable()?;
            let n = self.channel.read(&mut self.rx[self.decoder.tail..]).await?;
            self.decoder.commit(n);
        }
    }

    /// Try to decode a frame from data already buffered, without
    /// performing any IO.
    ///
    /// Returns:
    ///
    /// * `Ok(Some(frame))` — a complete frame was decoded.
    /// * `Ok(None)` — not enough bytes buffered yet; call again after
    ///   more data has been pumped in.
    /// * `Err(Protocol(PayloadTooLarge))` — the frame header advertises
    ///   a length that overflows `usize`.
    /// * `Err(ReceiveBufferFull)` — the buffer is completely full and
    ///   compaction cannot free any room.
    ///
    /// When a frame's payload exceeds the buffer size, the frame is
    /// delivered in multiple chunks: the caller receives several
    /// consecutive `Frame::Stdout` (or `Stderr` / `Other`) values
    /// whose payloads, concatenated, equal the original payload.
    ///
    /// Allocates a [`Vec`] for the payload. For throughput-sensitive
    /// streaming use [`try_next_raw_ref`](Self::try_next_raw_ref).
    pub fn try_next_frame(&mut self) -> Result<Option<Frame>, Error<<T as ErrorType>::Error>> {
        self.decoder
            .try_next_frame(self.rx)
            .map_err(Error::Protocol)
    }

    /// Zero-alloc counterpart to [`try_next_frame`](Self::try_next_frame):
    /// returns the raw `(id, payload)` pair with `payload` borrowing
    /// the shell's receive buffer.
    ///
    /// The returned slice is valid until the next call that pumps or
    /// compacts the buffer. Typical usage:
    ///
    /// ```ignore
    /// shell.pump(core::future::pending::<()>()).await?;
    /// while let Some((id, payload)) = shell.try_next_raw_ref()? {
    ///     // consume payload without allocating
    /// }
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn try_next_raw_ref(
        &mut self,
    ) -> Result<Option<(u8, &[u8])>, Error<<T as ErrorType>::Error>> {
        self.decoder
            .try_next_raw_ref(self.rx)
            .map_err(Error::Protocol)
    }

    /// Wait for more data on the channel — or for `interrupt` to resolve
    /// first — and append any received bytes to the receive buffer.
    ///
    /// After this returns [`SelectResult::Data`] the caller should drain
    /// frames with [`try_next_frame`](Self::try_next_frame) until it
    /// yields `None`, then call `pump` again.
    ///
    /// On [`SelectResult::Interrupted`] no bytes were appended and the
    /// caller can act on the interrupt before pumping again.
    ///
    /// Returns [`Error::ReceiveBufferFull`] if there is no free space
    /// in the buffer even after compaction.
    pub async fn pump<F: Future>(
        &mut self,
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<<T as ErrorType>::Error>> {
        self.ensure_writable()?;
        let result = self
            .channel
            .select(&mut self.rx[self.decoder.tail..], interrupt)
            .await?;
        if let SelectResult::Data(n) = &result {
            self.decoder.commit(*n);
        }
        Ok(result)
    }

    fn ensure_writable(&mut self) -> Result<(), Error<<T as ErrorType>::Error>> {
        if self.decoder.tail < self.rx.len() {
            return Ok(());
        }
        self.decoder.compact(self.rx);
        if self.decoder.tail == self.rx.len() {
            return Err(Error::ReceiveBufferFull);
        }
        Ok(())
    }

    /// Read frames until [`Frame::Exit`] is received, accumulating
    /// stdout/stderr along the way. Closes the channel before returning.
    pub async fn collect(mut self) -> Result<CommandOutput, Error<<T as ErrorType>::Error>> {
        let mut out = CommandOutput::default();
        loop {
            match self.read_frame().await? {
                Frame::Stdout(b) => out.stdout.extend_from_slice(&b),
                Frame::Stderr(b) => out.stderr.extend_from_slice(&b),
                Frame::Exit(code) => {
                    out.exit_code = code;
                    self.channel.close().await?;
                    return Ok(out);
                }
                Frame::Other { .. } => {}
            }
        }
    }

    /// Close the underlying channel without consuming any further frames.
    pub async fn close(self) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.channel.close().await
    }
}

/// Open a `shell,v2,raw:` channel against `conn`, wrap it in a [`Shell`]
/// using the caller-provided receive buffer, and return the wrapper.
/// Stdin remains open.
///
/// The channel borrows `conn`, so only one shell session can exist at a
/// time over a given connection. `rx` is the caller-owned receive
/// buffer; see [`Shell::new`] for details.
pub async fn open<'a, 'b, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    command: &str,
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    conn.require_feature(Feature::ShellV2)?;
    let dest = build_shell_v2_destination(false, "", command)?;
    let channel = conn.open(dest.as_bytes()).await?;
    Ok(Shell::new(channel, rx))
}

/// Open an interactive `shell,v2,pty` session with a PTY allocated on
/// the device.
///
/// * `command` — command to run inside the PTY. Pass an empty string
///   to start a login shell.
/// * `term` — value for the `TERM` environment variable on the device
///   (e.g. `"xterm-256color"`). Pass an empty string to omit it.
/// * `window_size` — if `Some((rows, cols))`, a [`WINDOW_SIZE_CHANGE`]
///   frame is sent right after the channel opens so the device PTY has
///   the correct dimensions from the start.
/// * `rx` — caller-owned receive buffer; see [`Shell::new`] for
///   sizing advice.
///
/// The returned [`Shell`] is ready for full-duplex use: call
/// [`Shell::pump`] in a loop, forward stdin with
/// [`Shell::write_stdin`], and handle resize events with
/// [`Shell::set_window_size`].
pub async fn open_interactive<'a, 'b, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    command: &str,
    term: &str,
    window_size: Option<(u16, u16)>,
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    conn.require_feature(Feature::ShellV2)?;
    let dest = build_shell_v2_destination(true, term, command)?;
    let channel = conn.open(dest.as_bytes()).await?;
    let mut shell = Shell::new(channel, rx);
    if let Some((rows, cols)) = window_size {
        shell.set_window_size(rows, cols).await?;
    }
    Ok(shell)
}

/// Run a one-shot command on the device, returning collected stdout,
/// stderr and the exit code.
///
/// High-level convenience: opens a `shell,v2,raw:` channel, closes
/// stdin immediately, drains all output frames and closes the channel.
/// `rx` is the caller-owned receive buffer — see [`Shell::new`] for
/// details.
///
/// `command` is shell source and reaches the device verbatim, so
/// metacharacters in it keep their meaning and anything interpolated
/// into it is the caller's to quote. [`cmd`](crate::cmd) quotes its
/// arguments, but it always runs Android's `cmd` utility — it is not a
/// general argv form of this call.
pub async fn exec<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    command: &str,
    rx: &mut [u8],
) -> Result<CommandOutput, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let mut shell = open(conn, command, rx).await?;
    shell.close_stdin().await?;
    shell.collect().await
}

mod decoder;
pub use decoder::FrameDecoder;

#[cfg(test)]
mod tests;
