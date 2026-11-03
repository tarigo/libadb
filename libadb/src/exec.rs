//! `exec:` service — raw, binary-clean command execution.
//!
//! Unlike [`shell::v1`](crate::shell::v1), the `exec:` service does not
//! allocate a PTY and does not perform CRLF conversion, so stdout is
//! suitable for binary payloads (e.g. `exec:cat /data/local/tmp/file`).
//! Like [`shell::v1`](crate::shell::v1), framing is absent — stdout and stderr are
//! interleaved on the channel and no exit code is reported. For exit
//! codes or separate streams use [`shell::v2`](crate::shell::v2) on
//! devices that advertise `shell_v2`.
//!
//! Two destination forms:
//!
//! * `exec:` — start the default shell (no PTY, stdin open).
//! * `exec:<command>` — run a single command via `sh -c`; the channel
//!   closes when the command exits.
//!
//! `command` is shell source and reaches the device verbatim, so
//! metacharacters in it keep their meaning and anything interpolated
//! into it is the caller's to quote. The argv-shaped APIs quote for
//! you, but they run one program each: [`cmd`](crate::cmd) and
//! [`abb`](crate::abb) run Android's `cmd`, [`logcat`](crate::logcat)
//! runs `logcat`.
//!
//! Zero-alloc: [`Exec`] wraps an open [`Channel`](crate::channel::Channel)
//! and all destination strings and output bytes land in caller-provided
//! byte slices. Use [`open`] for streaming use and [`exec()`] for a
//! one-shot command that collects output into a single caller-owned
//! buffer.

use crate::base::channel::ReadToEnd;
use crate::base::destination::{self, DestinationError};
use crate::base::session::Session;
use crate::error::Error;

fn write_destination(buf: &mut [u8], command: &str) -> Result<usize, DestinationError> {
    destination::write_destination(buf, &[b"exec:", command.as_bytes()], &[])
}

/// An `exec:` session: the same frameless byte stream a `shell:`
/// channel carries, minus the PTY. Construct via [`open`].
pub type Exec<'a, S> = crate::shell::v1::Shell<'a, S>;

/// Open an `exec:` channel and wrap it in an [`Exec`] session.
///
/// Pass an empty `command` to start the default shell; pass a command
/// string to run it via `sh -c` and have the channel close on exit.
///
/// `dest_buf` is a caller-owned scratch buffer used to assemble the
/// `exec:<command>\0` destination string. It must be at least
/// `command.len() + 6` bytes long; [`Error::ReceiveBufferFull`] is
/// returned otherwise. The buffer is free for reuse after this call
/// returns — opening copies the destination internally.
///
/// The channel borrows `session`, so only one exec session can exist
/// at a time over it. A split connection runs several at once, each over
/// its own clone of the [`Writer`](crate::Writer).
pub async fn open<'a, S: Session>(
    session: &'a mut S,
    command: &str,
    dest_buf: &mut [u8],
) -> Result<Exec<'a, S>, Error<S::IoError>> {
    let dest_len = write_destination(dest_buf, command)?;
    let channel = session.open(&dest_buf[..dest_len]).await?;
    Ok(Exec::new(channel))
}

/// Run a one-shot command over `exec:` and accumulate the combined
/// stdout+stderr bytes into `buf`.
///
/// Returns the number of bytes written to `buf` once the device closes
/// the channel. Returns [`Error::ReceiveBufferFull`] if the output
/// exceeds `buf.len()` (the already-read bytes stay in `buf[..tail]`
/// but the remainder of the output is lost). The same buffer is also
/// used transiently to build the `exec:<command>\0` destination string
/// before any output arrives.
///
/// Note: `exec:` provides no exit code. If the caller needs one, use
/// [`shell::v2::exec`](crate::shell::v2::exec) on devices that advertise
/// the `shell_v2` feature.
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

    #[test]
    fn destination_empty_command() {
        let mut buf = [0u8; 32];
        let n = write_destination(&mut buf, "").unwrap();
        assert_eq!(&buf[..n], b"exec:\0");
    }

    #[test]
    fn destination_with_command() {
        let mut buf = [0u8; 32];
        let n = write_destination(&mut buf, "cat /data/file").unwrap();
        assert_eq!(&buf[..n], b"exec:cat /data/file\0");
    }

    #[test]
    fn destination_buffer_exact_fit() {
        let mut buf = [0u8; 7];
        let n = write_destination(&mut buf, "x").unwrap();
        assert_eq!(&buf[..n], b"exec:x\0");
    }

    #[test]
    fn destination_buffer_too_small() {
        let mut buf = [0u8; 6];
        assert_eq!(
            write_destination(&mut buf, "x"),
            Err(DestinationError::TooLong)
        );
    }
}
