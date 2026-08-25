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
//! Zero-alloc: [`Exec`] wraps an open [`Channel`] and all destination
//! strings and output bytes land in caller-provided byte slices. Use
//! [`open`] for streaming use and [`run`] for a one-shot command that
//! collects output into a single caller-owned buffer.

use core::future::Future;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use crate::base::channel::{Channel, SelectResult};
use crate::base::connection::{
    Connection, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_FEATURES, DEFAULT_MAX_PROPERTIES,
};
use crate::base::destination::{self, DestinationError};
use crate::base::error::Error;

fn write_destination(buf: &mut [u8], command: &str) -> Result<usize, DestinationError> {
    destination::write_destination(buf, &[b"exec:", command.as_bytes()], &[])
}

/// `exec:` session. Construct via [`open`].
///
/// Provides named methods for reading the combined stdout+stderr byte
/// stream, forwarding stdin, and integrating with [`Channel::select`]
/// for full-duplex use. Output is binary-clean.
pub struct Exec<
    'a,
    T,
    const MAX_CHANNELS: usize = DEFAULT_MAX_CHANNELS,
    const MAX_PROPERTIES: usize = DEFAULT_MAX_PROPERTIES,
    const MAX_FEATURES: usize = DEFAULT_MAX_FEATURES,
> where
    T: Read + Write,
{
    channel: Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
}

impl<'a, T, const MAX_CHANNELS: usize, const MAX_PROPERTIES: usize, const MAX_FEATURES: usize>
    Exec<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    /// Read raw output bytes from the device into `buf`. Returns the
    /// number of bytes read.
    ///
    /// Output combines stdout and stderr in whatever order the device
    /// produced them. [`Error::ChannelClosed`] signals that the remote
    /// command has exited.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<<T as ErrorType>::Error>> {
        self.channel.read(buf).await
    }

    /// Send raw bytes to the device as stdin.
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.channel.write(data).await
    }

    /// Read from the channel, but return early if `interrupt` resolves
    /// first.
    ///
    /// After a [`SelectResult::Interrupted`] result the caller can act
    /// on the interrupt (e.g. forward stdin) and call `select` again —
    /// the channel state is unchanged and the next read will resume.
    pub async fn select<F: Future>(
        &mut self,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<<T as ErrorType>::Error>> {
        self.channel.select(buf, interrupt).await
    }

    /// Close the underlying channel.
    pub async fn close(self) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.channel.close().await
    }
}

/// Open an `exec:` channel and wrap it in an [`Exec`] session.
///
/// Pass an empty `command` to start the default shell; pass a command
/// string to run it via `sh -c` and have the channel close on exit.
///
/// `dest_buf` is a caller-owned scratch buffer used to assemble the
/// `exec:<command>\0` destination string. It must be at least
/// `command.len() + 6` bytes long; [`Error::ReceiveBufferFull`] is
/// returned otherwise. The buffer is free for reuse after this call
/// returns — [`Connection::open`] copies the destination internally.
///
/// The channel borrows `conn`, so only one exec session can exist at a
/// time over a given connection.
pub async fn open<'a, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    command: &str,
    dest_buf: &mut [u8],
) -> Result<Exec<'a, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let dest_len = write_destination(dest_buf, command)?;
    let channel = conn.open(&dest_buf[..dest_len]).await?;
    Ok(Exec { channel })
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
pub async fn run<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    command: &str,
    buf: &mut [u8],
) -> Result<usize, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let dest_len = write_destination(buf, command)?;
    let channel = conn.open(&buf[..dest_len]).await?;
    let mut session = Exec { channel };

    let mut tail = 0;
    loop {
        if tail >= buf.len() {
            return Err(Error::ReceiveBufferFull);
        }
        match session.read(&mut buf[tail..]).await {
            Ok(n) => tail += n,
            Err(Error::ChannelClosed) => {
                let _ = session.close().await;
                return Ok(tail);
            }
            Err(e) => return Err(e),
        }
    }
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
