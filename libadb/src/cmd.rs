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
//! without `abb` runs the same command as a device with it. An empty
//! argument takes the shell path even on a device with `abb`, which
//! [cannot carry one](crate::abb).
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

use crate::abb;
use crate::base::protocol::features::Feature;
use crate::base::session::Session;
use crate::error::Error;
use crate::shell::v2::{self as shell_v2, Shell};

const PROGRAM: &[u8] = b"cmd";

fn needs_shell(args: &[&str]) -> bool {
    args.iter().any(|arg| arg.is_empty())
}

/// Run a one-shot `cmd` command and collect all output.
///
/// Uses `abb_exec` when the device advertises it and no argument is
/// empty (fastest path, raw bytes); otherwise falls back to
/// `shell,v2,raw:cmd …`, closes its stdin, as
/// [`shell::v2::exec`](crate::shell::v2::exec) does, and collects stdout
/// via shell_v2. A device that lists neither `abb_exec` nor `shell_v2`
/// fails with [`Error::MissingFeature`], as does one without `shell_v2`
/// when an argument is empty.
///
/// `args` are the tokens that would follow `cmd` on the device shell.
/// For example, `cmd package list packages` is
/// `&["package", "list", "packages"]`. Each element arrives as one
/// argument: spaces and shell metacharacters inside it are literal, and
/// an embedded NUL is rejected with
/// [`ProtocolError::InvalidDestination`](crate::ProtocolError::InvalidDestination).
///
/// `rx` is a temporary buffer used for reading.
pub async fn exec<S: Session>(
    session: &mut S,
    args: &[&str],
    rx: &mut [u8],
) -> Result<Vec<u8>, Error<S::IoError>> {
    if session.advertises(&Feature::AbbExec) && !needs_shell(args) {
        return abb::exec(session, args, rx).await;
    }

    let channel = shell_v2::open_argv(session, PROGRAM, args, rx).await?;
    Ok(Shell::new(channel, rx).run_to_exit().await?.stdout)
}

/// Open a streaming `cmd` session.
///
/// Uses `abb` when the device advertises it and no argument is empty;
/// otherwise falls back to `shell,v2,raw:cmd …`.  Both paths return a
/// [`Shell`] handle for reading frames. A device that lists neither
/// `abb` nor `shell_v2` fails with [`Error::MissingFeature`], as does
/// one without `shell_v2` when an argument is empty.
///
/// `args` are the tokens that would follow `cmd` on the device shell,
/// one element per argument — see [`exec`] on how they are passed.
/// `rx` is the caller-owned receive buffer — see [`Shell::new`] for
/// sizing advice.
pub async fn open<'a, 'b, S: Session>(
    session: &'a mut S,
    args: &[&str],
    rx: &'b mut [u8],
) -> Result<Shell<'a, 'b, S>, Error<S::IoError>> {
    if session.advertises(&Feature::Abb) && !needs_shell(args) {
        return abb::open(session, args, rx).await;
    }

    let channel = shell_v2::open_argv(session, PROGRAM, args, rx).await?;
    Ok(Shell::new(channel, rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::destination::DestinationError;
    use crate::base::mock::{now, one_slot, shell_frame, wrte, Mock};
    use crate::base::protocol::command::Command;
    use crate::shell::v2::FrameId;
    use crate::Connection;

    /// The destination of the channel `conn` opened.
    fn opened(conn: &Connection<Mock>) -> Vec<u8> {
        let sent = conn.transport().sent();
        let open = sent.iter().find(|(cmd, ..)| *cmd == Command::Open);
        open.expect("a channel was opened").3.clone()
    }

    #[test]
    fn exec_takes_the_shell_path_past_abb_for_an_empty_argument() {
        let exit = wrte(1, &shell_frame(FrameId::Exit, &[0]));
        let mut conn = one_slot("abb_exec,shell_v2", &[exit]);
        let mut rx = [0u8; 64];

        now(exec(&mut conn, &["set", "", "x"], &mut rx)).unwrap();

        assert_eq!(opened(&conn), b"shell,v2,raw:cmd set '' x\0");
    }

    #[test]
    fn open_takes_the_shell_path_past_abb_for_an_empty_argument() {
        let mut conn = one_slot("abb,shell_v2", &[]);
        let mut rx = [0u8; 64];

        now(open(&mut conn, &["set", "", "x"], &mut rx))
            .map(drop)
            .unwrap();

        assert_eq!(opened(&conn), b"shell,v2,raw:cmd set '' x\0");
    }

    /// The destination the shell fallback opens for `args`.
    fn write_shell_destination(buf: &mut [u8], args: &[&str]) -> Result<usize, DestinationError> {
        shell_v2::write_argv_destination(buf, PROGRAM, args)
    }

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
