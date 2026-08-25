use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::error::ProtocolError;

pub(crate) fn build_shell_v2_destination(
    pty: bool,
    term: &str,
    command: &str,
) -> Result<String, ProtocolError> {
    if command.contains('\0') || term.contains('\0') {
        return Err(ProtocolError::InvalidDestination);
    }
    Ok(match (pty, term.is_empty()) {
        (false, _) => format!("shell,v2,raw:{command}\0"),
        (true, true) => format!("shell,v2,pty:{command}\0"),
        (true, false) => format!("shell,v2,pty,TERM={term}:{command}\0"),
    })
}

/// Why a destination could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationError {
    /// The destination does not fit the buffer the caller provided.
    TooLong,
    /// A NUL byte would have cut the destination short on the device.
    Nul,
}

impl<E> From<DestinationError> for super::error::Error<E> {
    fn from(e: DestinationError) -> Self {
        match e {
            DestinationError::TooLong => Self::ReceiveBufferFull,
            DestinationError::Nul => Self::Protocol(ProtocolError::InvalidDestination),
        }
    }
}

/// Write `prefixes` followed by shell-quoted `args`, NUL-terminated.
///
/// The destination reaches the device as one string that `adbd` hands
/// to `sh -c`, so an argument holding a space or a `;` would otherwise
/// become several arguments, or a second command. Quoting keeps each
/// element of `args` a single argument — the same guarantee
/// [`build_nul_destination`] gives on the `abb` path, so a call means
/// the same thing whichever service serves it.
///
/// `prefixes` are written verbatim: they carry the service name and,
/// for the string-shaped APIs, a command the caller wrote as shell
/// source on purpose.
pub(crate) fn write_destination(
    buf: &mut [u8],
    prefixes: &[&[u8]],
    args: &[&str],
) -> Result<usize, DestinationError> {
    // Checked up front, not as each piece is written: a buffer that
    // runs out early would otherwise report `TooLong` for input the
    // `abb` path rejects outright, and the two services would disagree
    // over the same call again.
    if prefixes.iter().any(|p| p.contains(&0)) || args.iter().any(|a| a.as_bytes().contains(&0)) {
        return Err(DestinationError::Nul);
    }
    let mut len = 0;
    for p in prefixes {
        len = write_bytes(buf, len, p)?;
    }
    for a in args {
        len = write_bytes(buf, len, b" ")?;
        len = write_quoted(buf, len, a.as_bytes())?;
    }
    write_bytes(buf, len, &[0])
}

fn write_bytes(buf: &mut [u8], len: usize, src: &[u8]) -> Result<usize, DestinationError> {
    let end = len
        .checked_add(src.len())
        .ok_or(DestinationError::TooLong)?;
    if end > buf.len() {
        return Err(DestinationError::TooLong);
    }
    buf[len..end].copy_from_slice(src);
    Ok(end)
}

/// Characters every POSIX shell passes through untouched — the set
/// `shlex.quote` uses. An argument built only from these is written as
/// it stands, which keeps ordinary destinations readable in logs.
fn is_shell_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
        )
}

fn write_quoted(buf: &mut [u8], len: usize, arg: &[u8]) -> Result<usize, DestinationError> {
    if !arg.is_empty() && arg.iter().all(|&b| is_shell_safe(b)) {
        return write_bytes(buf, len, arg);
    }
    // Single quotes suspend every shell expansion, and the one thing
    // they cannot hold is a single quote: close, escape it, reopen.
    let mut len = write_bytes(buf, len, b"'")?;
    for &b in arg {
        len = if b == b'\'' {
            write_bytes(buf, len, br"'\''")?
        } else {
            write_bytes(buf, len, &[b])?
        };
    }
    write_bytes(buf, len, b"'")
}

pub(crate) fn build_nul_destination(
    service: &str,
    args: &[&str],
) -> Result<Vec<u8>, ProtocolError> {
    if service.contains('\0') || args.iter().any(|a| a.contains('\0')) {
        return Err(ProtocolError::InvalidDestination);
    }
    let nul_terminated_args_len: usize = args.iter().map(|a| a.len() + 1).sum();
    let mut dest = Vec::with_capacity(service.len() + nul_terminated_args_len + 1);
    dest.extend_from_slice(service.as_bytes());
    for arg in args {
        dest.extend_from_slice(arg.as_bytes());
        dest.push(0);
    }
    if dest.last() != Some(&0) {
        dest.push(0);
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &[&[u8]] = &[b"shell,v2,raw:cmd"];

    fn rendered(args: &[&str]) -> String {
        let mut buf = [0u8; 256];
        let len = write_destination(&mut buf, CMD, args).unwrap();
        assert_eq!(buf[len - 1], 0, "destination must stay NUL-terminated");
        String::from_utf8(buf[..len - 1].to_vec()).unwrap()
    }

    #[test]
    fn a_shell_v2_destination_names_its_command() {
        let raw = build_shell_v2_destination(false, "", "ls").unwrap();
        assert_eq!(raw, "shell,v2,raw:ls\0");
        let pty = build_shell_v2_destination(true, "", "ls").unwrap();
        assert_eq!(pty, "shell,v2,pty:ls\0");
        let term = build_shell_v2_destination(true, "xterm", "ls").unwrap();
        assert_eq!(term, "shell,v2,pty,TERM=xterm:ls\0");
    }

    #[test]
    fn a_nul_in_either_half_of_a_shell_v2_destination_is_rejected() {
        assert_eq!(
            build_shell_v2_destination(false, "", "l\0s"),
            Err(ProtocolError::InvalidDestination)
        );
        assert_eq!(
            build_shell_v2_destination(true, "xte\0rm", "ls"),
            Err(ProtocolError::InvalidDestination)
        );
    }

    #[test]
    fn shell_safe_arguments_stay_bare() {
        assert_eq!(
            rendered(&["package", "list", "packages"]),
            "shell,v2,raw:cmd package list packages"
        );
        assert_eq!(
            rendered(&[
                "--user=0",
                "-l",
                "a,b",
                "/data/local/tmp/x.apk",
                "a.b:c%d+e@f"
            ]),
            "shell,v2,raw:cmd --user=0 -l a,b /data/local/tmp/x.apk a.b:c%d+e@f"
        );
    }

    #[test]
    fn spaces_do_not_split_an_argument() {
        assert_eq!(
            rendered(&["install", "/sdcard/My App.apk"]),
            "shell,v2,raw:cmd install '/sdcard/My App.apk'"
        );
    }

    #[test]
    fn shell_metacharacters_lose_their_meaning() {
        for evil in [
            ";reboot",
            "a|b",
            "x&&y",
            "$(id)",
            "`id`",
            ">/data/local/tmp/pwn",
            "*",
            "~root",
            "a\nb",
            "#comment",
        ] {
            assert_eq!(
                rendered(&["arg", evil]),
                format!("shell,v2,raw:cmd arg '{evil}'"),
                "{evil:?} must be quoted whole"
            );
        }
    }

    #[test]
    fn single_quotes_are_escaped() {
        assert_eq!(rendered(&["it's"]), r"shell,v2,raw:cmd 'it'\''s'");
        assert_eq!(rendered(&["'"]), r"shell,v2,raw:cmd ''\'''");
    }

    #[test]
    fn non_ascii_is_quoted_but_intact() {
        assert_eq!(rendered(&["привет"]), "shell,v2,raw:cmd 'привет'");
    }

    #[test]
    fn an_empty_argument_survives() {
        assert_eq!(rendered(&["set", "", "x"]), "shell,v2,raw:cmd set '' x");
    }

    #[test]
    fn a_nul_in_an_argument_is_rejected() {
        let mut buf = [0u8; 256];
        assert_eq!(
            write_destination(&mut buf, CMD, &["a\0b"]),
            Err(DestinationError::Nul)
        );
    }

    #[test]
    fn a_nul_in_a_prefix_is_rejected() {
        let mut buf = [0u8; 256];
        assert_eq!(
            write_destination(&mut buf, &[b"shell:", b"cat /x\0; rm -rf /"], &[]),
            Err(DestinationError::Nul)
        );
    }

    #[test]
    fn a_nul_outranks_a_buffer_that_is_too_small() {
        let mut buf = [0u8; 4];
        assert_eq!(
            write_destination(&mut buf, CMD, &["a\0b"]),
            Err(DestinationError::Nul)
        );
    }

    #[test]
    fn a_full_buffer_is_reported_as_too_long() {
        let mut buf = [0u8; 10];
        assert_eq!(
            write_destination(&mut buf, CMD, &["package"]),
            Err(DestinationError::TooLong)
        );
    }

    #[test]
    fn the_quotes_themselves_are_counted_against_the_buffer() {
        // Exactly enough for `p:` + ` a b` + NUL, but the quoting the
        // space forces needs two bytes more.
        let mut buf = [0u8; 7];
        assert_eq!(
            write_destination(&mut buf, &[b"p:"], &["a b"]),
            Err(DestinationError::TooLong)
        );
        let mut buf = [0u8; 9];
        let len = write_destination(&mut buf, &[b"p:"], &["a b"]).unwrap();
        assert_eq!(&buf[..len], b"p: 'a b'\0");
    }
}
