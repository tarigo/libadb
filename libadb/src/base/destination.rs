#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use crate::error::ProtocolError;

/// Why a destination could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationError {
    /// The destination does not fit the buffer the caller provided.
    TooLong,
    /// A NUL byte would have cut the destination short on the device.
    Nul,
}

impl<E> From<DestinationError> for crate::error::Error<E> {
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
