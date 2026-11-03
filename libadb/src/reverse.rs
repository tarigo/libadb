//! Reverse forwards (`adb reverse`): rules that make the device listen
//! on its side and open channels toward the host.
//!
//! Rules live on this connection — adbd drops them when it goes away.
//! Every connection the device then accepts arrives here as a
//! device-initiated OPEN whose destination is the rule's `<local>`
//! spec: receive them with
//! [`Connection::accept_incoming`](crate::Connection::accept_incoming)
//! (or `Reader::accept_incoming` on a split connection, and an
//! `IncomingListener` from `Writer::listen_incoming` while
//! `Reader::run` dispatches; without one, `run` refuses them).
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
use core::fmt;

use crate::base::channel::{Capped, ChannelId, ReadToEnd};
use crate::base::session::ServiceChannel;
use crate::error::{Error, ProtocolError};

/// Replies are tiny (a port number, a listing); anything past this is
/// not the service we think we are talking to.
const REPLY_CAP: usize = 64 * 1024;

/// What the `reverse:` rule service answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReverseError {
    /// The device returned `FAIL`. The message is adbd's own text,
    /// e.g. `bad forward: …` or `listener '…' not found`.
    Failed(Vec<u8>),
    /// The reply matched neither `OKAY` nor `FAIL`, or a *successful*
    /// reply's length prefix disagreed with what arrived. A `FAIL` is
    /// reported as [`Failed`](Self::Failed) even when its own length
    /// prefix is mangled — the device's message matters more than its
    /// framing.
    UnexpectedReply,
}

impl fmt::Display for ReverseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(msg) => {
                write!(f, "reverse service failed: ")?;
                match core::str::from_utf8(msg) {
                    Ok(m) => f.write_str(m),
                    Err(_) => write!(f, "{msg:?}"),
                }
            }
            Self::UnexpectedReply => f.write_str("unexpected reverse service reply"),
        }
    }
}

impl core::error::Error for ReverseError {}

impl<E> From<ReverseError> for Error<E> {
    fn from(e: ReverseError) -> Self {
        Self::Reverse(e)
    }
}

/// One rule in the device's listing, as [`list`] reads it.
///
/// The fields are the bytes the device sent: adbd prints its specs as
/// they were given, and nothing makes them UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseRule {
    /// The name adbd files the rule under, e.g. `host-19`: the
    /// connection that established it, as the device sees it.
    pub serial: Vec<u8>,
    /// The spec the device listens on, e.g. `tcp:6100`.
    pub remote: Vec<u8>,
    /// The spec each connection is opened toward on the host, e.g.
    /// `tcp:6100`.
    pub local: Vec<u8>,
}

/// Ask the device to listen on `device_spec` and forward every
/// connection to a channel opened toward the host with `host_spec` as
/// its destination.
///
/// Returns the port the device bound for a `tcp:` device spec — the
/// one it picked, for `tcp:0` — and `None` for any other spec, which
/// adbd answers with no port. A port that is not a decimal `u16` is
/// [`ReverseError::UnexpectedReply`].
pub async fn establish<C: ServiceChannel>(
    conn: &mut C,
    device_spec: &str,
    host_spec: &str,
) -> Result<Option<u16>, Error<C::IoError>> {
    check_specs(&[device_spec, host_spec])?;
    let mut dest = Vec::with_capacity(18 + device_spec.len() + host_spec.len());
    dest.extend_from_slice(b"reverse:forward:");
    dest.extend_from_slice(device_spec.as_bytes());
    dest.push(b';');
    dest.extend_from_slice(host_spec.as_bytes());
    dest.push(0);
    let reply = exchange(conn, &dest).await?;
    let data = parse_status(&reply).map_err(Error::Reverse)?;
    parse_port(&data).map_err(Error::Reverse)
}

/// Remove the rule listening on `device_spec`.
pub async fn remove<C: ServiceChannel>(
    conn: &mut C,
    device_spec: &str,
) -> Result<(), Error<C::IoError>> {
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
pub async fn remove_all<C: ServiceChannel>(conn: &mut C) -> Result<(), Error<C::IoError>> {
    let reply = exchange(conn, b"reverse:killforward-all\0").await?;
    parse_status(&reply).map_err(Error::Reverse)?;
    Ok(())
}

/// The device's current rules.
///
/// adbd prints each rule as a `<serial> <remote> <local>` line and
/// separates the fields with a bare space, so a space inside `local`
/// survives and one inside `remote` does not. The fields are kept as
/// bytes, so a spec that is not UTF-8 comes back like any other; a
/// line with fewer than three fields is
/// [`ReverseError::UnexpectedReply`].
pub async fn list<C: ServiceChannel>(conn: &mut C) -> Result<Vec<ReverseRule>, Error<C::IoError>> {
    let listing = list_raw(conn).await?;
    parse_listing(&listing).map_err(Error::Reverse)
}

/// The device's current rules as it sent them: the
/// `<serial> <remote> <local>\n` lines [`list`] parses, without the
/// reply's length prefix and unparsed, for a caller that passes the
/// listing on as text.
///
/// A `FAIL` is [`ReverseError::Failed`], and a reply that is not one
/// length-prefixed block is [`ReverseError::UnexpectedReply`]; the
/// lines themselves are not checked.
pub async fn list_raw<C: ServiceChannel>(conn: &mut C) -> Result<Vec<u8>, Error<C::IoError>> {
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
async fn exchange<C: ServiceChannel>(
    conn: &mut C,
    dest: &[u8],
) -> Result<Vec<u8>, Error<C::IoError>> {
    let ch = conn.open_service_channel(dest).await?;
    let mut buf = [0u8; 512];
    OpenedChannel { conn, ch }
        .read_to_vec(&mut buf, REPLY_CAP)
        .await?
        .map_err(|Capped| Error::Reverse(ReverseError::UnexpectedReply))
}

/// The channel [`exchange`] opened, paired with the [`ServiceChannel`]
/// it was opened on.
struct OpenedChannel<'c, C> {
    conn: &'c mut C,
    ch: ChannelId,
}

impl<C: ServiceChannel> ReadToEnd for OpenedChannel<'_, C> {
    type IoError = C::IoError;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<C::IoError>> {
        self.conn.read_service_channel(self.ch, buf).await
    }

    async fn close(self) -> Result<(), Error<C::IoError>> {
        self.conn.close_service_channel(self.ch).await
    }
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

/// The port in a successful `forward` reply: decimal digits, or nothing
/// for a spec that binds no port.
fn parse_port(data: &[u8]) -> Result<Option<u16>, ReverseError> {
    if data.is_empty() {
        return Ok(None);
    }
    // Byte-wise first, as in `hex4_block`: `u16::from_str` would also
    // take a leading `+`.
    if !data.iter().all(u8::is_ascii_digit) {
        return Err(ReverseError::UnexpectedReply);
    }
    core::str::from_utf8(data)
        .ok()
        .and_then(|digits| digits.parse().ok())
        .map(Some)
        .ok_or(ReverseError::UnexpectedReply)
}

/// The rules in a listing: one `<serial> <remote> <local>` per line.
fn parse_listing(block: &[u8]) -> Result<Vec<ReverseRule>, ReverseError> {
    if block.is_empty() {
        return Ok(Vec::new());
    }
    // The last line's `\n` ends it rather than opening another.
    let lines = block.strip_suffix(b"\n").unwrap_or(block);
    lines
        .split(|&b| b == b'\n')
        .map(|line| {
            let mut fields = line.splitn(3, |&b| b == b' ');
            match (fields.next(), fields.next(), fields.next()) {
                (Some(serial), Some(remote), Some(local)) => Ok(ReverseRule {
                    serial: serial.to_vec(),
                    remote: remote.to_vec(),
                    local: local.to_vec(),
                }),
                _ => Err(ReverseError::UnexpectedReply),
            }
        })
        .collect()
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
    use core::convert::Infallible;

    use super::*;
    use crate::base::mock::now;

    /// A [`ServiceChannel`] whose every read fails with
    /// [`Error::ReceiveBufferFull`].
    struct FullReads;

    impl ServiceChannel for FullReads {
        type IoError = Infallible;

        async fn open_service_channel(&mut self, _: &[u8]) -> Result<ChannelId, Error<Infallible>> {
            Ok(ChannelId::from_raw(0, 1))
        }

        async fn read_service_channel(
            &mut self,
            _: ChannelId,
            _: &mut [u8],
        ) -> Result<usize, Error<Infallible>> {
            Err(Error::ReceiveBufferFull)
        }

        async fn close_service_channel(&mut self, _: ChannelId) -> Result<(), Error<Infallible>> {
            Ok(())
        }
    }

    #[test]
    fn a_full_receive_buffer_is_not_taken_for_the_reply_cap() {
        let err = now(list(&mut FullReads)).unwrap_err();
        assert!(matches!(err, Error::ReceiveBufferFull), "got {err:?}");
    }

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

    fn rule(serial: &[u8], remote: &[u8], local: &[u8]) -> ReverseRule {
        ReverseRule {
            serial: serial.to_vec(),
            remote: remote.to_vec(),
            local: local.to_vec(),
        }
    }

    #[test]
    fn a_listing_parses_one_rule_per_line() {
        let listing = b"host-19 tcp:6100 tcp:6100\nhost-19 localabstract:a tcp:7\n";
        assert_eq!(
            parse_listing(listing).unwrap(),
            [
                rule(b"host-19", b"tcp:6100", b"tcp:6100"),
                rule(b"host-19", b"localabstract:a", b"tcp:7"),
            ]
        );
        assert_eq!(parse_listing(b"").unwrap(), []);
        assert_eq!(
            parse_listing(b"host-19 tcp:1 tcp:1").unwrap(),
            [rule(b"host-19", b"tcp:1", b"tcp:1")],
            "a last line without its newline"
        );
    }

    #[test]
    fn a_space_in_the_last_field_stays_in_it() {
        assert_eq!(
            parse_listing(b"host-19 tcp:1 localabstract:a b\n").unwrap(),
            [rule(b"host-19", b"tcp:1", b"localabstract:a b")]
        );
    }

    #[test]
    fn a_spec_that_is_not_utf8_comes_back_as_its_bytes() {
        // One such rule used to fail the whole listing.
        assert_eq!(
            parse_listing(b"host-19 tcp:1 localabstract:\xff\nhost-19 tcp:2 tcp:2\n").unwrap(),
            [
                rule(b"host-19", b"tcp:1", b"localabstract:\xff"),
                rule(b"host-19", b"tcp:2", b"tcp:2"),
            ]
        );
    }

    #[test]
    fn a_listing_that_is_not_rules_is_an_unexpected_reply() {
        for listing in [
            &b"host-19 tcp:1\n"[..],
            b"\n",
            b"host-19 tcp:1 tcp:1\n\nhost-19 tcp:2 tcp:2\n",
        ] {
            assert_eq!(
                parse_listing(listing),
                Err(ReverseError::UnexpectedReply),
                "{listing:?}"
            );
        }
    }

    #[test]
    fn a_bound_port_parses_as_decimal() {
        assert_eq!(parse_port(b"6100"), Ok(Some(6100)));
        assert_eq!(parse_port(b"65535"), Ok(Some(65535)));
        assert_eq!(parse_port(b""), Ok(None), "a spec that binds no port");
    }

    #[test]
    fn a_port_that_is_not_one_is_an_unexpected_reply() {
        for data in [&b"65536"[..], b"+80", b"-1", b"61 00", b"port", b"\xff"] {
            assert_eq!(
                parse_port(data),
                Err(ReverseError::UnexpectedReply),
                "{data:?}"
            );
        }
    }
}
