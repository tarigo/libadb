//! [`Error`], what every connection and service call fails with, and
//! the [`ProtocolError`] and [`AuthError`] it carries.
//!
//! Errors particular to one service live with it; [`SyncError`],
//! [`ReverseError`] and [`DecodeError`] are re-exported here as well.

#[cfg(test)]
mod tests;

use core::fmt::{self};

use crate::base::protocol::features::Feature;
use crate::base::protocol::Command;

pub use crate::base::protobuf::DecodeError;
pub use crate::reverse::ReverseError;
pub use crate::sync::SyncError;

/// ADB protocol error, parameterized over the transport IO error type.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// Transport IO error.
    Io(E),
    /// ADB protocol violation.
    Protocol(ProtocolError),
    /// Authentication failed.
    Auth(AuthError),
    /// Sync protocol error.
    Sync(SyncError),
    /// Reverse-forward service error.
    Reverse(ReverseError),
    /// Operation on a closed channel.
    ChannelClosed,
    /// All channel slots are occupied.
    NoFreeChannels,
    /// Transport closed unexpectedly (EOF during read).
    UnexpectedEof,
    /// A caller-provided receive buffer is too small for what it has to
    /// hold at once and cannot be grown. Returned by
    /// [`shell::v2::Shell`] when the buffer passed to
    /// [`shell::v2::Shell::new`] cannot fit either the next inbound
    /// frame or any further bytes from the channel after compaction, and
    /// by [`logcat::Logcat`] when its buffer cannot hold the next entry.
    ///
    /// [`shell::v2::Shell`]: crate::shell::v2::Shell
    /// [`shell::v2::Shell::new`]: crate::shell::v2::Shell::new
    /// [`logcat::Logcat`]: crate::logcat::Logcat
    ReceiveBufferFull,
    /// A channel buffered more unread data than
    /// [`ConnectionConfig::max_rx_per_channel`] allows.
    ///
    /// The last line of defence, not the usual brake: unread data holds
    /// back acknowledgements, so a device that respects flow control
    /// never gets past it, even with a full packet on its last byte of
    /// credit. Going past it means the peer kept writing without its
    /// window being re-opened. The connection is left intact but the
    /// offending packet was dropped unacknowledged, so that channel now
    /// has a gap in its byte stream — treat it as fatal for that channel.
    ///
    /// [`ConnectionConfig::max_rx_per_channel`]: crate::ConnectionConfig::max_rx_per_channel
    ChannelRxOverflow,
    /// A logcat session failed: its output did not parse or was cut
    /// short, or logcat exited with an error.
    Logcat(crate::logcat::LogcatError),
    /// The hex-framed protobuf of a [`track_app`](crate::track_app)
    /// snapshot did not decode.
    Decode(DecodeError),
    /// Device does not advertise a feature required by the attempted operation.
    MissingFeature(Feature),
    /// A packet may have been left half-written, so the byte stream can
    /// no longer be trusted to line up with what the device expects.
    ///
    /// A packet reaches the wire as a header write followed by a payload
    /// write. Dropping that future in between leaves the device reading
    /// the next bytes we send as the rest of the abandoned packet.
    /// The mark goes up from the moment the header write is first
    /// polled, and it is deliberately conservative: it also covers a
    /// write that was dropped or failed before any byte was
    /// acknowledged, because a transport that took bytes and then
    /// returned `Pending` or an error is indistinguishable from one that
    /// took none. Nothing can recover the framing from this side: close
    /// the connection and open a new one.
    ///
    /// Every later operation on the connection fails with this, except
    /// that a read first hands over what had already arrived for its
    /// channel: an abandoned write says nothing about bytes the device
    /// delivered. A split connection that had already ended stays
    /// [`Disconnected`](Self::Disconnected) for the calls waiting on the
    /// device, as when a read gives up on an acknowledgement at the end:
    /// only a write or a close can still meet this then.
    ///
    /// A write that failed because the device is gone is not such a
    /// write: the transport said connection reset or aborted, broken
    /// pipe or not connected, so there is no stream left to fall out of
    /// step with. The write fails with [`Error::Io`], and reads go on
    /// to receive what the device had sent.
    Desynchronized,
    /// A split connection has ended, so nothing more will arrive from
    /// the device: its `Reader::run` ended, the `Reader` was dropped, or
    /// a receive failed in a way that cannot be taken back. That is the
    /// end of the stream, a transport reporting the connection reset or
    /// aborted, a broken pipe or a device no longer connected, or a
    /// header that does not parse.
    ///
    /// The call that saw the receive fail gets that failure as it is;
    /// this is what every other call waiting on the device gets, once a
    /// read has handed over what its channel has buffered. A read that
    /// timed out says nothing about the connection and ends nothing.
    /// Waiting on such a connection would never end; open a new one.
    Disconnected,
}

/// What stopped the exchange at the protocol level: something from the
/// device that breaks the ADB protocol, something of ours it cannot
/// carry, or a handshake this connection does not follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Invalid command code.
    InvalidCommand(u32),
    /// Message magic field does not match command.
    InvalidMagic,
    /// Data checksum mismatch.
    InvalidChecksum,
    /// Payload exceeds negotiated max_payload.
    PayloadTooLarge,
    /// Received an unexpected command for the current state.
    UnexpectedCommand(Command),
    /// Delayed-ACK READY packet payload is shorter than 4 bytes.
    ShortReadyPayload,
    /// AUTH token is not the 20-byte SHA-1 prehash the handshake signs.
    /// Carries the length that arrived.
    InvalidAuthToken(usize),
    /// Shell v2 EXIT frame received with empty payload (expected 1-byte exit code).
    ShortExitPayload,
    /// Shell v2 frame with an id a device never sends: only stdout,
    /// stderr and exit frames come from it. Carries the id.
    UnexpectedShellFrame(u8),
    /// Service destination string contains an embedded NUL byte, or a
    /// shell_v2 `TERM` holds a `,` or `:` that would end it early and
    /// rewrite the request.
    InvalidDestination,
    /// Received an unknown feature from a device.
    UnknownFeature,
    /// Failed to convert the device banner to UTF-8.
    InvalidBannerUtf8,
    /// Device banner lacks a `<state>:<serial>:` prefix.
    InvalidBannerPrefix,
    /// Invalid key-value pair in the device banner.
    InvalidBannerKeyValue,
    /// Too many properties in the device banner: more than
    /// [`ConnectionConfig::max_banner_properties`](crate::ConnectionConfig::max_banner_properties).
    TooManyBannerProperties,
    /// The device answered the handshake with `STLS`: it speaks nothing
    /// but TLS from here on.
    ///
    /// This is how Android 11+ wireless debugging answers on the address
    /// and port its "Wireless debugging" screen shows. The pairing port
    /// is another thing: it speaks TLS from the first byte, and is for
    /// `pairing::pair`. The legacy port `adb tcpip` opens is plain text,
    /// and so is USB; neither is affected.
    ///
    /// With the `tls` feature, `Connection::connect_tls` takes the offer
    /// up.
    TlsRequired,
    /// More arrived in the clear behind the device's `STLS`.
    ///
    /// A TLS 1.3 server says nothing before the client's hello, so
    /// whatever follows `STLS` before the session starts is another
    /// plaintext packet, not the beginning of TLS.
    ///
    /// Returned by `Connection::connect_tls`. Only what arrived along
    /// with the `STLS` is caught here; plaintext sent later reaches the
    /// session and fails the handshake as a broken record.
    DataAfterStls,
}

/// Why the host did not get past authentication: the device refused it
/// or closed on it, or the authenticator would not sign or would not
/// offer its key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// Device rejected all authentication attempts.
    Rejected,
    /// The authenticator would not sign the token. Carries what it
    /// said, since that is the only account of the failure there is.
    SignFailed(alloc::string::String),
    /// The device did not accept the signature, and the authenticator
    /// chose not to offer the public key in its place.
    ///
    /// The device does not trust this key yet, and nothing has asked
    /// the user to: see
    /// [`Authenticator::offer_public_key`](crate::auth::Authenticator::offer_public_key).
    KeyNotTrusted,
    /// The device refused the certificate we offered: it does not have
    /// the key inside it.
    ///
    /// TLS 1.3 tells a client nothing when the server rejects its
    /// certificate: the certificate goes out in the client's last
    /// flight, so the handshake is over on our side before the device
    /// judges it, and the refusal arrives as an alert on the first
    /// read. adbd sends `certificate_unknown`; the other alerts a TLS
    /// stack may send over a certificate count too, `access_denied`
    /// among them. Authorise the key over USB, or run `adb pair`.
    TlsKeyNotTrusted,
    /// The device finished the TLS handshake and closed the session
    /// before any of its CNXN arrived.
    ///
    /// A device that refuses the key by closing looks like this, but so
    /// does one that took the key and then went away: adbd restarting,
    /// wireless debugging switched off, a reboot. If it keeps happening
    /// and the key was never paired or authorised, run `adb pair` or
    /// authorise it over USB.
    TlsClosedBeforeConnect,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid message magic"),
            Self::InvalidChecksum => f.write_str("data checksum mismatch"),
            Self::InvalidCommand(c) => f.write_fmt(format_args!("invalid command {}", c)),
            Self::PayloadTooLarge => f.write_str("payload exceeds max_payload"),
            // No word of `connect_tls`: a build without `tls` has none
            // to offer, and libadb-ffi words its own advice for C.
            Self::TlsRequired => f.write_str(
                "device requires a TLS handshake (Android 11+ wireless debugging) \
                 that this connection does not do; connect over USB, \
                 or switch the device to plain TCP with `adb tcpip 5555`",
            ),
            Self::DataAfterStls => {
                f.write_str("device sent more in the clear after STLS, where only TLS may follow")
            }
            Self::UnexpectedCommand(c) => f.write_fmt(format_args!("unexpected command {:?}", c)),
            Self::ShortReadyPayload => {
                f.write_str("delayed-ack READY payload shorter than 4 bytes")
            }
            Self::InvalidAuthToken(len) => f.write_fmt(format_args!(
                "AUTH token is {len} bytes, not the 20-byte SHA-1 prehash"
            )),
            Self::ShortExitPayload => f.write_str("shell v2 EXIT frame payload empty"),
            Self::UnexpectedShellFrame(id) => f.write_fmt(format_args!(
                "shell v2 frame id {id} is not one a device sends"
            )),
            Self::InvalidDestination => {
                f.write_str("service destination contains a NUL byte, or a ',' or ':' in its TERM")
            }
            Self::UnknownFeature => f.write_str("unknown feature"),
            Self::InvalidBannerUtf8 => f.write_str("failed to convert the device banner to UTF-8"),
            Self::InvalidBannerPrefix => f.write_str("invalid device banner prefix"),
            Self::InvalidBannerKeyValue => {
                f.write_str("invalid key-value pair in the device banner")
            }
            Self::TooManyBannerProperties => {
                f.write_str("too many properties in the device banner")
            }
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("authentication rejected"),
            Self::SignFailed(why) => f.write_fmt(format_args!("authenticator sign failed: {why}")),
            Self::KeyNotTrusted => f.write_str(
                "device does not trust this key, and the key was not offered for approval",
            ),
            Self::TlsKeyNotTrusted => f.write_str(
                "device does not trust this key over TLS; authorise it over USB or run `adb pair`",
            ),
            Self::TlsClosedBeforeConnect => f.write_str(
                "device closed the TLS session right after the handshake, before its CNXN; \
                 if this key was never paired or authorised, run `adb pair` or authorise it over USB",
            ),
        }
    }
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Auth(e) => write!(f, "auth: {e}"),
            Self::Sync(e) => write!(f, "{e}"),
            Self::Reverse(e) => write!(f, "{e}"),
            Self::ChannelClosed => f.write_str("channel closed"),
            Self::NoFreeChannels => f.write_str("no free channel slots"),
            Self::UnexpectedEof => f.write_str("unexpected eof"),
            Self::ReceiveBufferFull => f.write_str("receive buffer full"),
            Self::ChannelRxOverflow => {
                f.write_str("channel buffered more unread data than max_rx_per_channel allows")
            }
            Self::Logcat(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "{e}"),
            Self::MissingFeature(feature) => {
                write!(
                    f,
                    "device does not advertise feature {:?} ({})",
                    feature,
                    feature.wire_name()
                )
            }
            Self::Desynchronized => f.write_str("connection desynchronized by an unfinished write"),
            Self::Disconnected => f.write_str("connection ended"),
        }
    }
}

impl core::error::Error for ProtocolError {}

impl core::error::Error for AuthError {}

impl<E> core::error::Error for Error<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Auth(e) => Some(e),
            Self::Sync(e) => Some(e),
            Self::Reverse(e) => Some(e),
            Self::Logcat(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::ChannelClosed
            | Self::NoFreeChannels
            | Self::UnexpectedEof
            | Self::ReceiveBufferFull
            | Self::ChannelRxOverflow
            | Self::Desynchronized
            | Self::Disconnected
            | Self::MissingFeature(_) => None,
        }
    }
}

impl<E> From<ProtocolError> for Error<E> {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// A channel's receive buffer hit its configured cap. Internal marker
/// turned into [`Error::ChannelRxOverflow`] at the call sites that know
/// the transport error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RxOverflow;

impl<E> From<RxOverflow> for Error<E> {
    fn from(_: RxOverflow) -> Self {
        Self::ChannelRxOverflow
    }
}

/// Every slot of the channel table is taken. Internal marker turned
/// into [`Error::NoFreeChannels`] at the call sites that know the
/// transport error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoFreeChannels;

impl<E> From<NoFreeChannels> for Error<E> {
    fn from(_: NoFreeChannels) -> Self {
        Self::NoFreeChannels
    }
}

impl<E> From<AuthError> for Error<E> {
    fn from(e: AuthError) -> Self {
        Self::Auth(e)
    }
}

impl<E> From<crate::logcat::LogcatError> for Error<E> {
    fn from(e: crate::logcat::LogcatError) -> Self {
        Self::Logcat(e)
    }
}

impl<E> From<DecodeError> for Error<E> {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
