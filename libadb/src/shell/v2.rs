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

mod decoder;
#[cfg(test)]
mod tests;

pub use decoder::FrameDecoder;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;

use crate::base::channel::{Channel, SelectResult};
use crate::base::decimal::format_u32;
use crate::base::destination::{self as dest, DestinationError};
use crate::base::protocol::features::Feature;
use crate::base::session::Session;
use crate::error::{Error, ProtocolError};

/// The first byte of a frame: which stream or signal its payload
/// belongs to.
///
/// `FrameId::try_from` reads the byte and fails with the byte itself
/// for an id this enum does not name; `u8::from` gives the byte back.
///
/// ```
/// use libadb::shell::v2::FrameId;
///
/// assert_eq!(FrameId::try_from(1), Ok(FrameId::Stdout));
/// assert_eq!(u8::from(FrameId::Exit), 3);
/// assert_eq!(FrameId::try_from(9), Err(9));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameId {
    /// 0: stdin payload from host to device.
    Stdin,
    /// 1: stdout payload from device to host.
    Stdout,
    /// 2: stderr payload from device to host.
    Stderr,
    /// 3: exit code (1-byte payload) from device to host.
    Exit,
    /// 4: host signals that no more stdin will be sent.
    CloseStdin,
    /// 5: host notifies device of a terminal resize.
    WindowSizeChange,
}

impl TryFrom<u8> for FrameId {
    type Error = u8;

    fn try_from(id: u8) -> Result<Self, u8> {
        Ok(match id {
            0 => Self::Stdin,
            1 => Self::Stdout,
            2 => Self::Stderr,
            3 => Self::Exit,
            4 => Self::CloseStdin,
            5 => Self::WindowSizeChange,
            other => return Err(other),
        })
    }
}

impl From<FrameId> for u8 {
    fn from(id: FrameId) -> Self {
        match id {
            FrameId::Stdin => 0,
            FrameId::Stdout => 1,
            FrameId::Stderr => 2,
            FrameId::Exit => 3,
            FrameId::CloseStdin => 4,
            FrameId::WindowSizeChange => 5,
        }
    }
}

impl FrameId {
    /// The byte a header carried, whether or not [`FrameId`] names it:
    /// the id [`FrameDecoder::try_next_raw_ref`] hands back, flattened
    /// for a caller that only passes it on.
    ///
    /// ```
    /// use libadb::shell::v2::FrameId;
    ///
    /// assert_eq!(FrameId::byte_of(Ok(FrameId::Stderr)), 2);
    /// assert_eq!(FrameId::byte_of(Err(9)), 9);
    /// ```
    pub fn byte_of(id: Result<FrameId, u8>) -> u8 {
        match id {
            Ok(id) => id.into(),
            Err(byte) => byte,
        }
    }
}

/// Whether the device runs a shell_v2 command in a PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShellMode<'a> {
    /// `shell,v2,raw:` — no PTY: output arrives as the command wrote
    /// it, with stdout and stderr kept apart.
    Raw,
    /// `shell,v2,pty:` — the device allocates a PTY, as an interactive
    /// session needs, and stdout and stderr share it.
    Pty {
        /// What `TERM` is set to on the device, e.g.
        /// `"xterm-256color"`; `None` leaves the device's default, and
        /// so does an empty name.
        ///
        /// It may not hold a `,`, a `:` or a NUL: each would end the
        /// name early and rewrite the request, so [`destination`]
        /// refuses it.
        term: Option<&'a str>,
    },
}

/// The NUL-terminated destination that opens `command` in `mode`:
/// `shell,v2,raw:<command>\0`, `shell,v2,pty:<command>\0` or
/// `shell,v2,pty,TERM=<term>:<command>\0`.
///
/// `command` is shell source and reaches the device verbatim; an empty
/// one starts a login shell. A NUL in `command` or the terminal name
/// would cut the destination short on the device, so it fails with
/// [`ProtocolError::InvalidDestination`].
///
/// So does a `,` or `:` in the terminal name. adbd reads the options up
/// to the first `:` and splits them on `,`, the last mode named
/// winning: `TERM=xterm,raw` would drop the PTY, and `TERM=xterm:x`
/// would run `x:<command>`. The command itself may hold either.
///
/// ```
/// use libadb::shell::v2::{destination, ShellMode};
///
/// let pty = ShellMode::Pty { term: Some("xterm") };
/// assert_eq!(destination(pty, "ls").unwrap(), "shell,v2,pty,TERM=xterm:ls\0");
/// assert_eq!(destination(ShellMode::Raw, "ls").unwrap(), "shell,v2,raw:ls\0");
///
/// let rewritten = ShellMode::Pty { term: Some("xterm,raw") };
/// assert!(destination(rewritten, "ls").is_err());
/// ```
pub fn destination(mode: ShellMode<'_>, command: &str) -> Result<String, ProtocolError> {
    if command.contains('\0') {
        return Err(ProtocolError::InvalidDestination);
    }
    Ok(match mode {
        ShellMode::Raw => format!("shell,v2,raw:{command}\0"),
        ShellMode::Pty {
            term: None | Some(""),
        } => format!("shell,v2,pty:{command}\0"),
        ShellMode::Pty { term: Some(term) } => {
            if term.contains([',', ':', '\0']) {
                return Err(ProtocolError::InvalidDestination);
            }
            format!("shell,v2,pty,TERM={term}:{command}\0")
        }
    })
}

/// Size of the framing header in bytes.
pub const HEADER_SIZE: usize = 5;

/// A header's id, or the byte it holds when [`FrameId`] does not name
/// it, and its payload length.
pub(crate) fn parse_header(buf: &[u8; HEADER_SIZE]) -> (Result<FrameId, u8>, u32) {
    let length = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    (FrameId::try_from(buf[0]), length)
}

/// A terminal's size in character cells: what a
/// [`WindowSizeChange`](FrameId::WindowSizeChange) frame tells the
/// device's PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct WindowSize {
    /// Height, in rows.
    pub rows: u16,
    /// Width, in columns.
    pub cols: u16,
}

impl WindowSize {
    /// The frame's payload as adbd reads it:
    /// `<rows>x<cols>,<xpixels>x<ypixels>` in ASCII decimal and
    /// NUL-terminated, with the pixel size sent as `0x0` since only
    /// rows and columns are known here.
    ///
    /// adbd parses it with `sscanf(data, "%dx%d,%dx%d", …)` in
    /// `Subprocess::PassInput` (`adb/daemon/shell_service.cpp`), and
    /// the `adb` client builds it with the matching `snprintf` in
    /// `adb/client/commandline.cpp`. A payload that does not match is
    /// dropped without a word, and the PTY keeps its old size.
    ///
    /// ```
    /// use libadb::shell::v2::WindowSize;
    ///
    /// let size = WindowSize { rows: 24, cols: 80 };
    /// assert_eq!(size.encode().as_bytes(), b"24x80,0x0\0");
    /// ```
    pub fn encode(&self) -> EncodedWindowSize {
        let mut out = EncodedWindowSize {
            bytes: [0; EncodedWindowSize::MAX_LEN],
            len: 0,
        };
        let mut digits = [0; 10];
        out.push(format_u32(self.rows.into(), &mut digits));
        out.push(b"x");
        out.push(format_u32(self.cols.into(), &mut digits));
        out.push(b",0x0\0");
        out
    }
}

/// A [`WindowSize`] as its frame carries it, held on the stack: see
/// [`WindowSize::encode`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncodedWindowSize {
    bytes: [u8; Self::MAX_LEN],
    len: usize,
}

impl EncodedWindowSize {
    /// The longest payload there is: `65535x65535,0x0` and its NUL.
    pub const MAX_LEN: usize = "65535x65535,0x0\0".len();

    /// The payload, NUL included.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Append `part`. Only [`WindowSize::encode`] calls it, and what it
    /// appends never comes to more than `MAX_LEN`.
    fn push(&mut self, part: &[u8]) {
        let end = self.len + part.len();
        self.bytes[self.len..end].copy_from_slice(part);
        self.len = end;
    }
}

impl AsRef<[u8]> for EncodedWindowSize {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for EncodedWindowSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = core::str::from_utf8(self.as_bytes()).unwrap_or("<not ASCII>");
        f.debug_tuple("EncodedWindowSize").field(&text).finish()
    }
}

/// A decoded shell_v2 frame produced by [`Shell::read_frame`] /
/// [`Shell::try_next_frame`].
#[derive(Debug, Clone)]
pub enum Frame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// `EXIT` payload — the device process exit code.
    Exit(u8),
    /// A frame that is neither stdout, stderr nor exit: one with an id
    /// [`FrameId`] does not name, or one only a host sends. The raw
    /// payload is returned as-is.
    Other {
        /// The id byte as it arrived.
        id: u8,
        /// The payload, untouched.
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
/// The caller supplies one fixed-size byte slice in [`new`](Self::new),
/// which receives every channel read and holds the frames being
/// assembled. `Shell` allocates nothing on the heap but the [`Vec<u8>`]
/// inside each [`Frame`] it returns. If one in-progress frame fills the
/// slice, operations return [`Error::ReceiveBufferFull`]. Frames whose
/// payload exceeds the buffer size are delivered in multiple chunks
/// transparently.
pub struct Shell<'a, 'b, S> {
    channel: Channel<'a, S>,
    rx: &'b mut [u8],
    decoder: FrameDecoder,
}

impl<'a, 'b, S: Session> Shell<'a, 'b, S> {
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
    /// Panics if `rx.len() < HEADER_SIZE`: a buffer smaller than the
    /// 5-byte header cannot decode any frame at all.
    pub fn new(channel: Channel<'a, S>, rx: &'b mut [u8]) -> Self {
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
    /// Allocates nothing: the frame is assembled in the free tail of
    /// `rx` when it fits there, and otherwise header and payload go as
    /// two channel writes. shell_v2 is stream-oriented, so the receiver
    /// reassembles from the byte stream regardless of WRTE boundaries.
    pub async fn send_frame(
        &mut self,
        id: FrameId,
        payload: &[u8],
    ) -> Result<(), Error<S::IoError>> {
        let len_u32 = u32::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge)?;
        let hdr: [u8; HEADER_SIZE] = {
            let b = len_u32.to_le_bytes();
            [id.into(), b[0], b[1], b[2], b[3]]
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
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<(), Error<S::IoError>> {
        self.send_frame(FrameId::Stdin, data).await
    }

    /// Send a `CLOSE_STDIN` frame, telling the device that no further
    /// stdin will be written.
    ///
    /// A channel the device has already closed is not a failure, so a
    /// command that finished first still gives
    /// [`collect`](Self::collect) its output and exit code. A channel a
    /// fault closed fails all the same, with that fault's error, such as
    /// [`Error::ChannelRxOverflow`].
    pub async fn close_stdin(&mut self) -> Result<(), Error<S::IoError>> {
        match self.send_frame(FrameId::CloseStdin, &[]).await {
            Err(Error::ChannelClosed) => Ok(()),
            sent => sent,
        }
    }

    /// Send a `WINDOW_SIZE_CHANGE` frame telling the device's PTY its
    /// new `size`.
    pub async fn set_window_size(&mut self, size: WindowSize) -> Result<(), Error<S::IoError>> {
        self.send_frame(FrameId::WindowSizeChange, size.encode().as_bytes())
            .await
    }

    /// Read the next decoded frame, blocking until one is available.
    ///
    /// The end of the stream is reported by the channel as
    /// [`Error::ChannelClosed`]. Returns [`Error::ReceiveBufferFull`] if
    /// the caller-provided receive buffer cannot fit the frame currently
    /// being assembled.
    pub async fn read_frame(&mut self) -> Result<Frame, Error<S::IoError>> {
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
    pub fn try_next_frame(&mut self) -> Result<Option<Frame>, Error<S::IoError>> {
        self.decoder
            .try_next_frame(self.rx)
            .map_err(Error::Protocol)
    }

    /// Zero-alloc counterpart to [`try_next_frame`](Self::try_next_frame):
    /// returns the raw `(id, payload)` pair with `payload` borrowing
    /// the shell's receive buffer. `id` is the byte itself when
    /// [`FrameId`] does not name it.
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
    ) -> Result<Option<(Result<FrameId, u8>, &[u8])>, Error<S::IoError>> {
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
    /// caller can act on the interrupt before pumping again. How early
    /// an interrupt can win depends on the session and its transport:
    /// see [`Channel::select`].
    ///
    /// Returns [`Error::ReceiveBufferFull`] if there is no free space
    /// in the buffer even after compaction.
    pub async fn pump<F: Future>(
        &mut self,
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<S::IoError>> {
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

    fn ensure_writable(&mut self) -> Result<(), Error<S::IoError>> {
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
    /// stdout/stderr along the way, then close the channel.
    ///
    /// The device closing without an exit frame is
    /// [`Error::ChannelClosed`]. The close goes out on every way out,
    /// since nothing else frees the slot ([`Channel`] has no `Drop`). It
    /// is best-effort: the result of the reads is returned, not the
    /// close's, so a close that fails costs a finished command none of
    /// its output.
    pub async fn collect(mut self) -> Result<CommandOutput, Error<S::IoError>> {
        let mut out = CommandOutput::default();
        let read = loop {
            match self.read_frame().await {
                Ok(Frame::Stdout(b)) => out.stdout.extend_from_slice(&b),
                Ok(Frame::Stderr(b)) => out.stderr.extend_from_slice(&b),
                Ok(Frame::Exit(code)) => {
                    out.exit_code = code;
                    break Ok(out);
                }
                Ok(Frame::Other { .. }) => {}
                Err(e) => break Err(e),
            }
        };
        let _ = self.channel.close().await;
        read
    }

    /// What a one-shot does with the shell it opened: close stdin, then
    /// [`collect`](Self::collect). A `CLOSE_STDIN` that fails ends it
    /// there, the channel closed all the same.
    pub(crate) async fn run_to_exit(mut self) -> Result<CommandOutput, Error<S::IoError>> {
        if let Err(e) = self.close_stdin().await {
            let _ = self.close().await;
            return Err(e);
        }
        self.collect().await
    }

    /// Close the underlying channel without consuming any further frames.
    pub async fn close(self) -> Result<(), Error<S::IoError>> {
        self.channel.close().await
    }
}

/// Open a `shell,v2,raw:` channel on `session`, wrap it in a [`Shell`]
/// using the caller-provided receive buffer, and return the wrapper.
/// Stdin remains open.
///
/// The channel borrows `session`, so only one shell session can exist
/// at a time over it. A split connection runs several at once, each over
/// its own clone of the [`Writer`](crate::Writer). `rx` is the
/// caller-owned receive buffer; see [`Shell::new`] for details.
pub async fn open<'a, 'b, S: Session>(
    session: &'a mut S,
    command: &str,
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, S>, Error<S::IoError>> {
    session.require_feature(Feature::ShellV2)?;
    let dest = destination(ShellMode::Raw, command)?;
    let channel = session.open(dest.as_bytes()).await?;
    Ok(Shell::new(channel, rx))
}

/// Open an interactive `shell,v2,pty` session with a PTY allocated on
/// the device.
///
/// * `command` — command to run inside the PTY. Pass an empty string
///   to start a login shell.
/// * `term` — value for the `TERM` environment variable on the device
///   (e.g. `"xterm-256color"`); `None` or an empty name leaves the
///   device's default. One holding a `,`, `:` or NUL fails with
///   [`ProtocolError::InvalidDestination`], as [`destination`] says.
/// * `window_size` — if `Some`, a
///   [`WindowSizeChange`](FrameId::WindowSizeChange) frame is sent
///   right after the channel opens so the device PTY has
///   the correct dimensions from the start. If that fails, the channel
///   is closed again and the failure comes back.
/// * `rx` — caller-owned receive buffer; see [`Shell::new`] for
///   sizing advice.
///
/// The returned [`Shell`] is ready for full-duplex use: call
/// [`Shell::pump`] in a loop, forward stdin with
/// [`Shell::write_stdin`], and handle resize events with
/// [`Shell::set_window_size`].
pub async fn open_interactive<'a, 'b, S: Session>(
    session: &'a mut S,
    command: &str,
    term: Option<&str>,
    window_size: Option<WindowSize>,
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, S>, Error<S::IoError>> {
    session.require_feature(Feature::ShellV2)?;
    let dest = destination(ShellMode::Pty { term }, command)?;
    let channel = session.open(dest.as_bytes()).await?;
    let mut shell = Shell::new(channel, rx);
    if let Some(size) = window_size {
        if let Err(e) = shell.set_window_size(size).await {
            let _ = shell.close().await;
            return Err(e);
        }
    }
    Ok(shell)
}

/// Run a one-shot command on the device, returning collected stdout,
/// stderr and the exit code.
///
/// High-level convenience: opens a `shell,v2,raw:` channel, closes
/// stdin immediately, drains all output frames and closes the channel,
/// on every way out once it is open. `rx` is the caller-owned receive
/// buffer — see [`Shell::new`] for details.
///
/// `command` is shell source and reaches the device verbatim, so
/// metacharacters in it keep their meaning and anything interpolated
/// into it is the caller's to quote. [`cmd`](crate::cmd) quotes its
/// arguments, but it always runs Android's `cmd` utility — it is not a
/// general argv form of this call.
pub async fn exec<S: Session>(
    session: &mut S,
    command: &str,
    rx: &mut [u8],
) -> Result<CommandOutput, Error<S::IoError>> {
    open(session, command, rx).await?.run_to_exit().await
}

/// Write `shell,v2,raw:<prefix> <args…>\0` into `buf`: `prefix` as it
/// stands, each of `args` quoted so it reaches the device as one
/// argument.
pub(crate) fn write_argv_destination(
    buf: &mut [u8],
    prefix: &[u8],
    args: &[&str],
) -> Result<usize, DestinationError> {
    dest::write_destination(buf, &[b"shell,v2,raw:", prefix], args)
}

/// Open the channel [`write_argv_destination`] names, once the device
/// is known to speak shell_v2. The destination is built in `buf`, so a
/// `buf` too short for it is [`Error::ReceiveBufferFull`].
pub(crate) async fn open_argv<'a, S: Session>(
    session: &'a mut S,
    prefix: &[u8],
    args: &[&str],
    buf: &mut [u8],
) -> Result<Channel<'a, S>, Error<S::IoError>> {
    session.require_feature(Feature::ShellV2)?;
    let dest_len = write_argv_destination(buf, prefix, args)?;
    session.open(&buf[..dest_len]).await
}
