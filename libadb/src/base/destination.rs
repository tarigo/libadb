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

pub(crate) fn write_destination(
    buf: &mut [u8],
    prefixes: &[&[u8]],
    args: &[&str],
) -> Option<usize> {
    let mut len = 0;
    for p in prefixes {
        if len + p.len() > buf.len() {
            return None;
        }
        buf[len..len + p.len()].copy_from_slice(p);
        len += p.len();
    }
    for a in args {
        let ab = a.as_bytes();
        if len + 1 + ab.len() >= buf.len() {
            return None;
        }
        buf[len] = b' ';
        len += 1;
        buf[len..len + ab.len()].copy_from_slice(ab);
        len += ab.len();
    }
    if len >= buf.len() {
        return None;
    }
    buf[len] = 0;
    len += 1;
    Some(len)
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
