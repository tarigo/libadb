//! Run `cmd` commands on the device with automatic transport selection.
//!
//! The `cmd` utility on Android communicates with system services.  This
//! module provides a unified API that picks the best available transport:
//!
//! | Priority | Transport | One-shot | Streaming |
//! |---|---|---|---|
//! | 1 | `abb_exec` / `abb` | raw bytes | shell_v2 framing |
//! | 2 | `shell,v2,raw:cmd …` | shell_v2 | shell_v2 framing |
//!
//! `args` is an argv either way: the `abb` services take NUL-separated
//! arguments, and the shell fallback quotes each one, so a device
//! without `abb` runs the same command as a device with it.
//!
//! # Examples
//!
//! ```ignore
//! // One-shot: list installed packages
//! let mut rx = [0u8; 64 * 1024];
//! let output = cmd::exec(&mut conn, &["package", "list", "packages"], &mut rx).await?;
//! let text = core::str::from_utf8(&output).unwrap();
//!
//! // Streaming: monitor activities
//! let mut session = cmd::open(&mut conn, &["activity", "monitor"], &mut rx).await?;
//! loop {
//!     match session.read_frame().await? {
//!         Frame::Stdout(data) => { /* … */ }
//!         Frame::Exit(code) => break,
//!         _ => {}
//!     }
//! }
//! ```

use alloc::vec::Vec;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use crate::abb;
use crate::base::connection::Connection;
use crate::base::destination::{self, DestinationError};
use crate::base::error::Error;
use crate::base::protocol::features::Feature;
use crate::shell::v2::Shell;

fn write_shell_destination(buf: &mut [u8], args: &[&str]) -> Result<usize, DestinationError> {
    destination::write_destination(buf, &[b"shell,v2,raw:cmd"], args)
}

fn has_feature<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &Connection<T, MC, MP, MF>,
    feature: &Feature,
) -> bool
where
    T: Read + Write,
{
    conn.device_banner_parsed()
        .is_some_and(|b| b.has_feature(feature))
}

/// Run a one-shot `cmd` command and collect all output.
///
/// Uses `abb_exec` when the device advertises it (fastest path, raw
/// bytes); otherwise falls back to `shell,v2,raw:cmd …` and collects
/// stdout via shell_v2.
///
/// `args` are the tokens that would follow `cmd` on the device shell.
/// For example, `cmd package list packages` is
/// `&["package", "list", "packages"]`. Each element arrives as one
/// argument: spaces and shell metacharacters inside it are literal, and
/// an embedded NUL is rejected with
/// [`ProtocolError::InvalidDestination`](crate::ProtocolError::InvalidDestination).
///
/// `rx` is a temporary buffer used for reading.
pub async fn exec<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    args: &[&str],
    rx: &mut [u8],
) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    if has_feature(conn, &Feature::AbbExec) {
        return abb::exec(conn, args, rx).await;
    }

    let dest_len = write_shell_destination(rx, args)?;
    let channel = conn.open(&rx[..dest_len]).await?;
    let shell = Shell::new(channel, rx);
    let output = shell.collect().await?;
    Ok(output.stdout)
}

/// Open a streaming `cmd` session.
///
/// Uses `abb` when the device advertises it; otherwise falls back to
/// `shell,v2,raw:cmd …`.  Both paths return a [`Shell`] handle for
/// reading frames.
///
/// `args` are the tokens that would follow `cmd` on the device shell,
/// one element per argument — see [`exec`] on how they are passed.
/// `rx` is the caller-owned receive buffer — see [`Shell::new`] for
/// sizing advice.
pub async fn open<'a, 'b, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    args: &[&str],
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    if has_feature(conn, &Feature::Abb) {
        return abb::open(conn, args, rx).await;
    }

    let dest_len = write_shell_destination(rx, args)?;
    let channel = conn.open(&rx[..dest_len]).await?;
    Ok(Shell::new(channel, rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_destination_multiple_args() {
        let mut buf = [0u8; 128];
        let len = write_shell_destination(&mut buf, &["package", "list", "packages"]).unwrap();
        assert_eq!(&buf[..len], b"shell,v2,raw:cmd package list packages\0");
    }

    #[test]
    fn shell_destination_single_arg() {
        let mut buf = [0u8; 128];
        let len = write_shell_destination(&mut buf, &["connectivity"]).unwrap();
        assert_eq!(&buf[..len], b"shell,v2,raw:cmd connectivity\0");
    }

    #[test]
    fn shell_destination_no_args() {
        let mut buf = [0u8; 128];
        let len = write_shell_destination(&mut buf, &[]).unwrap();
        assert_eq!(&buf[..len], b"shell,v2,raw:cmd\0");
    }

    #[test]
    fn shell_destination_buffer_too_small() {
        let mut buf = [0u8; 10];
        assert_eq!(
            write_shell_destination(&mut buf, &["package"]),
            Err(DestinationError::TooLong)
        );
    }
}
