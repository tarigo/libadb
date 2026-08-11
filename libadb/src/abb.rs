//! Android Binder Bridge (ABB) protocol.
//!
//! Available on Android 10+ devices that advertise the `abb` or `abb_exec`
//! feature, ABB lets the host invoke Android service commands (the `cmd`
//! tool) through binder without spawning a shell process.
//!
//! Two channel types with **different wire formats**:
//!
//! | Destination | Wire format | Use case |
//! |---|---|---|
//! | `abb_exec:<arg0>\0<arg1>\0…` | **Raw** — plain stdout bytes | One-shot command |
//! | `abb:<arg0>\0<arg1>\0…` | **shell_v2** framing | Interactive / streaming |
//!
//! Arguments are the tokens you would pass to `cmd` on the device.
//! For example, `cmd package list packages` becomes
//! `&["package", "list", "packages"]`.
//!
//! # Examples
//!
//! ```ignore
//! // One-shot: list installed packages (raw output)
//! let mut rx = [0u8; 64 * 1024];
//! let output = abb::exec(&mut conn, &["package", "list", "packages"], &mut rx).await?;
//! // output is Vec<u8> of raw stdout
//!
//! // Interactive / streaming (shell_v2 framed)
//! let mut session = abb::open(&mut conn, &["activity", "monitor"], &mut rx).await?;
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

use crate::base::channel::Channel;
use crate::base::connection::Connection;
use crate::base::destination::build_nul_destination;
use crate::base::error::Error;
use crate::base::protocol::features::Feature;
use crate::shell::v2::Shell;

/// Open a raw `abb_exec:` channel. The device sends plain stdout bytes
/// (no shell_v2 framing) and closes the channel when the command
/// finishes.
///
/// `args` are the tokens that would follow `cmd` on the device shell.
/// For example, to run `cmd package list packages -3` pass
/// `&["package", "list", "packages", "-3"]`.
pub async fn open_exec<'a, T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &'a mut Connection<T, MC, MP, MF>,
    args: &[&str],
) -> Result<Channel<'a, T, MC, MP, MF>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    conn.require_feature(Feature::AbbExec)?;
    let dest = build_nul_destination("abb_exec:", args)?;
    conn.open(&dest).await
}

/// Run a one-shot ABB command, returning the raw stdout output.
///
/// Opens an `abb_exec:` channel, reads all output until the device
/// closes the channel, and returns the collected bytes.
///
/// `args` are the tokens that would follow `cmd` on the device shell.
/// `rx` is used as a temporary read buffer (not retained after return).
pub async fn exec<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    args: &[&str],
    rx: &mut [u8],
) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let mut channel = open_exec(conn, args).await?;
    let mut output = Vec::new();
    loop {
        match channel.read(rx).await {
            Ok(n) => output.extend_from_slice(&rx[..n]),
            Err(Error::ChannelClosed) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(output)
}

/// Open an interactive `abb:` channel for streaming or bidirectional
/// communication with an Android service.
///
/// Uses shell_v2 framing — the caller reads frames via
/// [`Shell::read_frame`] / [`Shell::pump`] and writes stdin via
/// [`Shell::write_stdin`].
///
/// `args` are the tokens that would follow `cmd` on the device shell.
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
    conn.require_feature(Feature::Abb)?;
    let dest = build_nul_destination("abb:", args)?;
    let channel = conn.open(&dest).await?;
    Ok(Shell::new(channel, rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_abb_exec_multiple_args() {
        let dest = build_nul_destination("abb_exec:", &["package", "list", "packages"]).unwrap();
        assert_eq!(dest, b"abb_exec:package\0list\0packages\0");
    }

    #[test]
    fn destination_abb_single_arg() {
        let dest = build_nul_destination("abb:", &["connectivity"]).unwrap();
        assert_eq!(dest, b"abb:connectivity\0");
    }

    #[test]
    fn destination_no_args() {
        let dest = build_nul_destination("abb_exec:", &[]).unwrap();
        assert_eq!(dest, b"abb_exec:\0");
    }

    #[test]
    fn destination_rejects_nul_in_arg() {
        use crate::base::error::ProtocolError;
        assert_eq!(
            build_nul_destination("abb_exec:", &["bad\0arg"]),
            Err(ProtocolError::InvalidDestination)
        );
    }
}
