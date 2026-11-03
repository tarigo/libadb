//! Shell v1 (legacy) protocol on top of an ADB channel.
//!
//! Unlike [`shell::v2`](crate::shell::v2), the legacy `shell:` service has
//! no framing: the channel carries a raw byte stream with stdout and
//! stderr interleaved, and the exit code is not reported. The device
//! always allocates a PTY — there is no way to request a raw (non-TTY)
//! session or to set `TERM` / window size.
//!
//! Two destination forms:
//!
//! * `shell:` — start the default shell interactively (PTY allocated).
//! * `shell:<command>` — run a single command inside a PTY; the channel
//!   closes when the command exits.
//!
//! This module is zero-alloc: [`Shell`] wraps an open [`Channel`] and
//! all destination strings and output bytes land in caller-provided
//! byte slices. Use [`open`] for interactive / streaming use, and
//! [`exec`] for a one-shot command that collects output into a single
//! caller-owned buffer.

use core::future::Future;

use crate::base::channel::{Channel, ReadToEnd, SelectResult};
use crate::base::destination::{self, DestinationError};
use crate::base::session::Session;
use crate::error::Error;

fn write_destination(buf: &mut [u8], command: &str) -> Result<usize, DestinationError> {
    destination::write_destination(buf, &[b"shell:", command.as_bytes()], &[])
}

/// Shell v1 (legacy) session. Construct via [`open`].
///
/// Provides named methods for reading the combined stdout+stderr byte
/// stream, forwarding stdin, and integrating with [`Channel::select`]
/// for full-duplex interactive sessions.
///
/// Unlike [`shell::v2::Shell`](crate::shell::v2::Shell), the v1 protocol is
/// frameless — `read` returns raw bytes as they arrive and `write_stdin`
/// sends raw bytes to the device's TTY. There is no separate stderr
/// stream and no exit code.
pub struct Shell<'a, S> {
    channel: Channel<'a, S>,
}

impl<'a, S: Session> Shell<'a, S> {
    /// Read raw output bytes from the device into `buf`. Returns the
    /// number of bytes read.
    ///
    /// Output combines stdout and stderr in whatever order the device
    /// produced them. [`Error::ChannelClosed`] signals that the remote
    /// command has exited.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<S::IoError>> {
        self.channel.read(buf).await
    }

    /// Send raw bytes to the device as stdin.
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<(), Error<S::IoError>> {
        self.channel.write(data).await
    }

    /// Read from the channel, but return early if `interrupt` resolves
    /// first.
    ///
    /// On a transport whose reads cannot be cancelled without losing
    /// data (USB), the interrupt is checked between reads: one already
    /// in flight completes first and may return its data ahead of a
    /// ready interrupt — see
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
    ///
    /// After a [`SelectResult::Interrupted`] result the caller can act
    /// on the interrupt (e.g. forward stdin) and call `select` again —
    /// the channel state is unchanged and the next read will resume.
    pub async fn select<F: Future>(
        &mut self,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<S::IoError>> {
        self.channel.select(buf, interrupt).await
    }

    /// Close the underlying channel.
    pub async fn close(self) -> Result<(), Error<S::IoError>> {
        self.channel.close().await
    }
}

/// Open a legacy `shell:` channel and wrap it in a [`Shell`].
///
/// Pass an empty `command` to start a default interactive shell; pass a
/// command string to run it inside a PTY and have the channel close on
/// exit.
///
/// `dest_buf` is a caller-owned scratch buffer used to assemble the
/// `shell:<command>\0` destination string. It must be at least
/// `command.len() + 7` bytes long; [`Error::ReceiveBufferFull`] is
/// returned otherwise. The buffer is free for reuse after this call
/// returns — opening copies the destination internally.
///
/// The channel borrows `session`, so only one shell session can exist
/// at a time over it. A split connection runs several at once, each over
/// its own clone of the [`Writer`](crate::Writer).
pub async fn open<'a, S: Session>(
    session: &'a mut S,
    command: &str,
    dest_buf: &mut [u8],
) -> Result<Shell<'a, S>, Error<S::IoError>> {
    let dest_len = write_destination(dest_buf, command)?;
    let channel = session.open(&dest_buf[..dest_len]).await?;
    Ok(Shell { channel })
}

/// Run a one-shot command over `shell:` and accumulate the combined
/// stdout+stderr bytes into `buf`.
///
/// Returns the number of bytes written to `buf` once the device closes
/// the channel. Returns [`Error::ReceiveBufferFull`] if the output
/// exceeds `buf.len()` (the already-read bytes stay in `buf[..tail]`
/// but the remainder of the output is lost). The same buffer is also
/// used transiently to build the `shell:<command>\0` destination string
/// before any output arrives.
///
/// `command` is shell source and reaches the device verbatim, so
/// metacharacters in it keep their meaning and anything interpolated
/// into it is the caller's to quote. [`cmd`](crate::cmd) quotes its
/// arguments, but it always runs Android's `cmd` utility — it is not a
/// general argv form of this call.
///
/// Note: the legacy protocol provides no exit code. If the caller needs
/// one, use [`shell::v2::exec`](crate::shell::v2::exec) on devices that
/// advertise the `shell_v2` feature.
pub async fn exec<S: Session>(
    session: &mut S,
    command: &str,
    buf: &mut [u8],
) -> Result<usize, Error<S::IoError>> {
    let dest_len = write_destination(buf, command)?;
    let channel = session.open(&buf[..dest_len]).await?;
    channel.read_to_end(buf).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::mock::{now, okay, one_slot, wrte, MockError};
    use crate::base::protocol::Packet;

    /// Run a one-shot `exec` the device answers with `answer` on a
    /// connection of one channel slot, then open another channel in that
    /// slot. Returns how the exec failed.
    fn exec_fails_then_slot_reopens(answer: &[Packet]) -> Error<MockError> {
        let mut conn = one_slot("shell_v2", answer);
        let mut buf = [0u8; 16];
        let err = now(exec(&mut conn, "yes", &mut buf)).unwrap_err();

        conn.transport_mut().feed(&okay(2));
        now(conn.open_channel(b"shell:\0")).expect("the failed exec kept its slot");
        err
    }

    #[test]
    fn exec_frees_its_slot_when_the_buffer_fills() {
        let err = exec_fails_then_slot_reopens(&[wrte(1, &[b'y'; 16])]);
        assert!(matches!(err, Error::ReceiveBufferFull), "got {err:?}");
    }

    #[test]
    fn exec_frees_its_slot_when_a_read_fails() {
        // Nothing follows the OKAY: the read runs into the end of the
        // transport.
        let err = exec_fails_then_slot_reopens(&[]);
        assert!(matches!(err, Error::UnexpectedEof), "got {err:?}");
    }

    #[test]
    fn destination_empty_command() {
        let mut buf = [0u8; 32];
        let n = write_destination(&mut buf, "").unwrap();
        assert_eq!(&buf[..n], b"shell:\0");
    }

    #[test]
    fn destination_with_command() {
        let mut buf = [0u8; 32];
        let n = write_destination(&mut buf, "ls /sdcard").unwrap();
        assert_eq!(&buf[..n], b"shell:ls /sdcard\0");
    }

    #[test]
    fn destination_buffer_exact_fit() {
        let mut buf = [0u8; 8];
        let n = write_destination(&mut buf, "x").unwrap();
        assert_eq!(&buf[..n], b"shell:x\0");
    }

    #[test]
    fn destination_buffer_too_small() {
        let mut buf = [0u8; 7];
        assert_eq!(
            write_destination(&mut buf, "x"),
            Err(DestinationError::TooLong)
        );
    }
}
