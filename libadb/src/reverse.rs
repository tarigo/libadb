//! Reverse forwards (`adb reverse`): rules that make the device listen
//! on its side and open channels toward the host.
//!
//! Rules live on this connection — adbd drops them when it goes away.
//! Every connection the device then accepts arrives here as a
//! device-initiated OPEN whose destination is the rule's `<local>`
//! spec: receive them with
//! [`Connection::accept_incoming`](crate::Connection::accept_incoming)
//! (or `Reader::accept_incoming` on a split connection).
//!
//! Specs are passed through verbatim, e.g. `tcp:8080` or
//! `localabstract:name`. On the device, adbd binds `tcp:` listeners on
//! its wildcard address — connecting locally over IPv6 (`::1`) is what
//! works in practice.
//!
//! Wire format, verified against a real adbd:
//!
//! * `reverse:forward:<remote>;<local>` → `OKAY` + `%04x` + data; for
//!   `tcp:` remotes the data is the bound port in decimal (`tcp:0`
//!   asks adbd to pick one);
//! * `reverse:killforward:<remote>`, `reverse:killforward-all` →
//!   bare `OKAY`;
//! * `reverse:list-forward` → no `OKAY`, just `%04x` + lines of
//!   `<serial> <remote> <local>\n`;
//! * any failure → `FAIL` + `%04x` + message.

use alloc::vec::Vec;

use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use crate::base::connection::Connection;
use crate::base::error::{Error, ProtocolError, ReverseError};

/// Replies are tiny (a port number, a listing); anything past this is
/// not the service we think we are talking to.
const REPLY_CAP: usize = 64 * 1024;

/// Ask the device to listen on `device_spec` and forward every
/// connection to a channel opened toward the host with `host_spec` as
/// its destination.
///
/// Returns the service's data bytes: for `tcp:` device specs this is
/// the bound port in decimal (useful with `tcp:0`), empty otherwise.
pub async fn establish<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    device_spec: &str,
    host_spec: &str,
) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    check_specs(&[device_spec, host_spec])?;
    let mut dest = Vec::with_capacity(18 + device_spec.len() + host_spec.len());
    dest.extend_from_slice(b"reverse:forward:");
    dest.extend_from_slice(device_spec.as_bytes());
    dest.push(b';');
    dest.extend_from_slice(host_spec.as_bytes());
    dest.push(0);
    let reply = exchange(conn, &dest).await?;
    parse_status(&reply).map_err(Error::Reverse)
}

/// Remove the rule listening on `device_spec`.
pub async fn remove<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    device_spec: &str,
) -> Result<(), Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    check_specs(&[device_spec])?;
    let mut dest = Vec::with_capacity(21 + device_spec.len());
    dest.extend_from_slice(b"reverse:killforward:");
    dest.extend_from_slice(device_spec.as_bytes());
    dest.push(0);
    let reply = exchange(conn, &dest).await?;
    parse_status(&reply).map_err(Error::Reverse)?;
    Ok(())
}

/// Remove every rule this connection established.
pub async fn remove_all<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
) -> Result<(), Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let reply = exchange(conn, b"reverse:killforward-all\0").await?;
    parse_status(&reply).map_err(Error::Reverse)?;
    Ok(())
}

/// The device's current rules, as adbd prints them: lines of
/// `<serial> <remote> <local>\n`.
pub async fn list<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let reply = exchange(conn, b"reverse:list-forward\0").await?;
    // The listing skips OKAY: it is just a hex4-prefixed block. A
    // failure still arrives as FAIL + hex4 + message, and the two
    // cannot collide — `I` and `L` are not hex digits.
    if reply.starts_with(b"FAIL") {
        return Err(Error::Reverse(fail_message(&reply[4..])));
    }
    hex4_block(&reply).ok_or(Error::Reverse(ReverseError::UnexpectedReply))
}

/// A NUL would cut the service string short on the device, making the
/// rule differ from the requested one — reject it like the other
/// string-taking APIs do.
fn check_specs<E>(specs: &[&str]) -> Result<(), Error<E>> {
    if specs.iter().any(|s| s.contains('\0')) {
        return Err(Error::Protocol(ProtocolError::InvalidDestination));
    }
    Ok(())
}

/// Open the service channel, read until the device closes it.
async fn exchange<T, const MC: usize, const MP: usize, const MF: usize>(
    conn: &mut Connection<T, MC, MP, MF>,
    dest: &[u8],
) -> Result<Vec<u8>, Error<<T as ErrorType>::Error>>
where
    T: Read + Write,
{
    let ch = conn.open_channel(dest).await?;
    let mut reply = Vec::new();
    let mut buf = [0u8; 512];
    let result = loop {
        match conn.read_channel(ch, &mut buf).await {
            Ok(n) => {
                // Checked before extending: the buffer must never grow
                // past the cap, not even transiently for the chunk
                // that busts it.
                if reply.len() + n > REPLY_CAP {
                    break Err(Error::Reverse(ReverseError::UnexpectedReply));
                }
                reply.extend_from_slice(&buf[..n]);
            }
            Err(Error::ChannelClosed) => break Ok(reply),
            Err(e) => break Err(e),
        }
    };
    // The remote CLSE only marks the slot closed; freeing it takes a
    // close of our own, on every exit — otherwise each call leaks a
    // slot until NoFreeChannels. Best-effort: `result` wins.
    let _ = conn.close_channel(ch).await;
    result
}

/// `OKAY`[+hex4+data] → data; `FAIL`+hex4+msg → `Failed`.
fn parse_status(reply: &[u8]) -> Result<Vec<u8>, ReverseError> {
    match reply.get(..4) {
        Some(b"OKAY") => {
            let rest = &reply[4..];
            if rest.is_empty() {
                Ok(Vec::new())
            } else {
                hex4_block(rest).ok_or(ReverseError::UnexpectedReply)
            }
        }
        Some(b"FAIL") => Err(fail_message(&reply[4..])),
        _ => Err(ReverseError::UnexpectedReply),
    }
}

/// `FAIL`'s payload: the device's message, verbatim when the length
/// prefix itself is mangled.
fn fail_message(rest: &[u8]) -> ReverseError {
    ReverseError::Failed(hex4_block(rest).unwrap_or_else(|| rest.to_vec()))
}

/// A `%04x` length followed by exactly that many bytes.
fn hex4_block(b: &[u8]) -> Option<Vec<u8>> {
    let prefix = b.get(..4)?;
    // Checked byte-wise: `from_str_radix` alone would also take a
    // leading sign, letting `+001` pass for a one-byte block.
    if !prefix.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let digits = core::str::from_utf8(prefix).ok()?;
    let len = usize::from_str_radix(digits, 16).ok()?;
    let body = b.get(4..)?;
    if body.len() != len {
        return None;
    }
    Some(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_parse_as_probed_on_a_real_device() {
        assert_eq!(parse_status(b"OKAY00046100").unwrap(), b"6100");
        assert_eq!(parse_status(b"OKAY").unwrap(), b"");
        assert_eq!(
            parse_status(b"FAIL0014bad forward: garbage").unwrap_err(),
            ReverseError::Failed(b"bad forward: garbage".to_vec())
        );
        assert_eq!(
            parse_status(b"MEOW").unwrap_err(),
            ReverseError::UnexpectedReply
        );
        assert_eq!(
            parse_status(b"OKAY000461").unwrap_err(),
            ReverseError::UnexpectedReply
        );
        assert_eq!(hex4_block(b"0000").unwrap(), b"");
        assert_eq!(
            hex4_block(b"001ahost-19 tcp:6100 tcp:6100\n").unwrap(),
            b"host-19 tcp:6100 tcp:6100\n"
        );
        // A signed prefix is not four hex digits, however happily
        // `from_str_radix` would take it.
        assert_eq!(hex4_block(b"+0011"), None);
        assert_eq!(
            parse_status(b"OKAY+0011").unwrap_err(),
            ReverseError::UnexpectedReply
        );
    }
}
