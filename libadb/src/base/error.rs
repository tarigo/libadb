use alloc::vec::Vec;
use core::fmt::{self};

use super::protocol::features::Feature;
use super::protocol::Command;

pub use super::protobuf::DecodeError;

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
    /// A caller-provided receive buffer is too small to hold the next
    /// frame and cannot be grown. Returned by [`shell::v2::Shell`] when
    /// the buffer passed to [`shell::v2::Shell::new`] cannot fit either
    /// the next inbound frame or any further bytes from the channel
    /// after compaction.
    ///
    /// [`shell::v2::Shell`]: crate::shell::v2::Shell
    /// [`shell::v2::Shell::new`]: crate::shell::v2::Shell::new
    ReceiveBufferFull,
    /// A channel buffered more unread data than
    /// [`ConnectionConfig::max_rx_per_channel`] allows.
    ///
    /// The last line of defence, not the usual brake: unread data now
    /// holds back acknowledgements, so a device that respects flow
    /// control stops on its own well before this. Reaching it means the
    /// peer kept writing without its window being re-opened. The
    /// connection is left intact but the offending packet was dropped
    /// unacknowledged, so that channel now has a gap in its byte stream
    /// — treat it as fatal for that channel.
    ///
    /// [`ConnectionConfig::max_rx_per_channel`]: crate::ConnectionConfig::max_rx_per_channel
    ChannelRxOverflow,
    /// Logcat binary entry parsing error.
    Logcat(crate::logcat::LogcatError),
    /// Hex-framed protobuf decode error (track-app, app-info).
    Decode(DecodeError),
    /// Device does not advertise a feature required by the attempted operation.
    MissingFeature(Feature),
    /// A packet may have been left half-written, so the byte stream can
    /// no longer be trusted to line up with what the device expects.
    ///
    /// Raised by every later operation on the connection. A packet
    /// reaches the wire as a header write followed by a payload write;
    /// dropping that future in between leaves the device reading the
    /// next bytes we send as the rest of the abandoned packet.
    ///
    /// The judgement is deliberately conservative: it also covers a
    /// write that was polled and then dropped or failed before any byte
    /// was acknowledged, because a transport that took bytes and then
    /// returned `Pending` or an error is indistinguishable from one
    /// that took none. Nothing can recover the framing from this side —
    /// close the connection and open a new one.
    Desynchronized,
}

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
    /// Shell v2 EXIT frame received with empty payload (expected 1-byte exit code).
    ShortExitPayload,
    /// Service destination string contains an embedded NUL byte.
    InvalidDestination,
    /// Received an unknown feature from a device.
    UnknownFeature,
    /// Failed to convert the device banner to UTF-8.
    InvalidBannerUtf8,
    /// Device banner lacks a `<state>:<serial>:` prefix.
    InvalidBannerPrefix,
    /// Invalid key-value pair in the device banner.
    InvalidBannerKeyValue,
    /// Too many properties in the device banner.
    TooManyBannerProperties,
    /// Too many features in the device banner.
    TooManyBannerFeatures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// Device rejected all authentication attempts.
    Rejected,
    /// Authenticator failed to sign the token.
    SignFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncError {
    /// Device returned a `FAIL` response. The message is truncated to
    /// the session buffer when the device sent more than it holds.
    Failed(Vec<u8>),
    /// Unexpected sync response command ID.
    UnexpectedId([u8; 4]),
    /// `STA2` / `LIS2` reported a non-zero error code (device errno).
    RemoteErrno(u32),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid message magic"),
            Self::InvalidChecksum => f.write_str("data checksum mismatch"),
            Self::InvalidCommand(c) => f.write_fmt(format_args!("invalid command {}", c)),
            Self::PayloadTooLarge => f.write_str("payload exceeds max_payload"),
            Self::UnexpectedCommand(c) => f.write_fmt(format_args!("unexpected command {:?}", c)),
            Self::ShortReadyPayload => {
                f.write_str("delayed-ack READY payload shorter than 4 bytes")
            }
            Self::ShortExitPayload => f.write_str("shell v2 EXIT frame payload empty"),
            Self::InvalidDestination => f.write_str("service destination contains a NUL byte"),
            Self::UnknownFeature => f.write_str("unknown feature"),
            Self::InvalidBannerUtf8 => f.write_str("failed to convert the device banner to UTF-8"),
            Self::InvalidBannerPrefix => f.write_str("invalid device banner prefix"),
            Self::InvalidBannerKeyValue => {
                f.write_str("invalid key-value pair in the device banner")
            }
            Self::TooManyBannerProperties => {
                f.write_str("too many properties in the device banner")
            }
            Self::TooManyBannerFeatures => f.write_str("too many features in the device banner"),
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("authentication rejected"),
            Self::SignFailed => f.write_str("authenticator sign failed"),
        }
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(msg) => {
                let s = core::str::from_utf8(msg).unwrap_or("<non-utf8>");
                write!(f, "sync: device error: {s}")
            }
            Self::UnexpectedId(id) => {
                let s = core::str::from_utf8(id).unwrap_or("????");
                write!(f, "sync: unexpected response: {s}")
            }
            Self::RemoteErrno(e) => write!(f, "sync: remote errno {e}"),
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
        }
    }
}

impl core::error::Error for ProtocolError {}

impl core::error::Error for AuthError {}

impl core::error::Error for SyncError {}

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

impl<E> From<AuthError> for Error<E> {
    fn from(e: AuthError) -> Self {
        Self::Auth(e)
    }
}

impl<E> From<SyncError> for Error<E> {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}

impl<E> From<ReverseError> for Error<E> {
    fn from(e: ReverseError) -> Self {
        Self::Reverse(e)
    }
}

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

#[cfg(test)]
mod tests {
    use super::{AuthError, DecodeError, Error, ProtocolError, SyncError};
    use crate::base::protocol::features::Feature;
    use crate::base::protocol::Command;
    use crate::logcat::LogcatError;
    use alloc::format;
    use alloc::vec;
    use core::fmt;

    #[derive(Debug)]
    struct IoStub;

    impl fmt::Display for IoStub {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("io-stub")
        }
    }

    impl core::error::Error for IoStub {}

    fn show<E: fmt::Display>(e: &E) -> alloc::string::String {
        format!("{}", e)
    }

    #[test]
    fn protocol_display_invalid_magic() {
        assert_eq!(show(&ProtocolError::InvalidMagic), "invalid message magic");
    }

    #[test]
    fn protocol_display_invalid_checksum() {
        assert_eq!(
            show(&ProtocolError::InvalidChecksum),
            "data checksum mismatch"
        );
    }

    #[test]
    fn protocol_display_invalid_command_embeds_raw_code() {
        assert_eq!(
            show(&ProtocolError::InvalidCommand(0xDEAD_BEEF)),
            format!("invalid command {}", 0xDEAD_BEEFu32)
        );
    }

    #[test]
    fn protocol_display_payload_too_large() {
        assert_eq!(
            show(&ProtocolError::PayloadTooLarge),
            "payload exceeds max_payload"
        );
    }

    #[test]
    fn protocol_display_unexpected_command_uses_debug_of_command() {
        assert_eq!(
            show(&ProtocolError::UnexpectedCommand(Command::Write)),
            "unexpected command Write"
        );
    }

    #[test]
    fn protocol_display_unknown_feature() {
        assert_eq!(show(&ProtocolError::UnknownFeature), "unknown feature");
    }

    #[test]
    fn protocol_display_banner_variants() {
        assert_eq!(
            show(&ProtocolError::InvalidBannerUtf8),
            "failed to convert the device banner to UTF-8"
        );
        assert_eq!(
            show(&ProtocolError::InvalidBannerPrefix),
            "invalid device banner prefix"
        );
        assert_eq!(
            show(&ProtocolError::InvalidBannerKeyValue),
            "invalid key-value pair in the device banner"
        );
        assert_eq!(
            show(&ProtocolError::TooManyBannerProperties),
            "too many properties in the device banner"
        );
        assert_eq!(
            show(&ProtocolError::TooManyBannerFeatures),
            "too many features in the device banner"
        );
    }

    #[test]
    fn auth_display_rejected_and_sign_failed() {
        assert_eq!(show(&AuthError::Rejected), "authentication rejected");
        assert_eq!(show(&AuthError::SignFailed), "authenticator sign failed");
    }

    #[test]
    fn sync_display_failed_utf8_message() {
        assert_eq!(
            show(&SyncError::Failed(b"no such file".to_vec())),
            "sync: device error: no such file"
        );
    }

    #[test]
    fn sync_display_failed_non_utf8_message_falls_back_to_placeholder() {
        assert_eq!(
            show(&SyncError::Failed(vec![0xff, 0xfe, 0xfd])),
            "sync: device error: <non-utf8>"
        );
    }

    #[test]
    fn sync_display_unexpected_id_ascii() {
        assert_eq!(
            show(&SyncError::UnexpectedId(*b"FAIL")),
            "sync: unexpected response: FAIL"
        );
    }

    #[test]
    fn sync_display_unexpected_id_non_utf8_falls_back_to_question_marks() {
        assert_eq!(
            show(&SyncError::UnexpectedId([0xff, 0xfe, 0xfd, 0xfc])),
            "sync: unexpected response: ????"
        );
    }

    #[test]
    fn sync_display_remote_errno() {
        assert_eq!(show(&SyncError::RemoteErrno(2)), "sync: remote errno 2");
    }

    #[test]
    fn error_display_io_uses_inner() {
        let e: Error<IoStub> = Error::Io(IoStub);
        assert_eq!(show(&e), "io: io-stub");
    }

    #[test]
    fn error_display_protocol_is_prefixed() {
        let e: Error<IoStub> = Error::Protocol(ProtocolError::InvalidMagic);
        assert_eq!(show(&e), "protocol: invalid message magic");
    }

    #[test]
    fn error_display_auth_is_prefixed() {
        let e: Error<IoStub> = Error::Auth(AuthError::Rejected);
        assert_eq!(show(&e), "auth: authentication rejected");
    }

    #[test]
    fn error_display_sync_keeps_inner_prefix_only() {
        let e: Error<IoStub> = Error::Sync(SyncError::RemoteErrno(13));
        assert_eq!(show(&e), "sync: remote errno 13");
    }

    #[test]
    fn error_display_channel_closed() {
        let e: Error<IoStub> = Error::ChannelClosed;
        assert_eq!(show(&e), "channel closed");
    }

    #[test]
    fn error_display_no_free_channels() {
        let e: Error<IoStub> = Error::NoFreeChannels;
        assert_eq!(show(&e), "no free channel slots");
    }

    #[test]
    fn error_display_unexpected_eof() {
        let e: Error<IoStub> = Error::UnexpectedEof;
        assert_eq!(show(&e), "unexpected eof");
    }

    #[test]
    fn error_display_receive_buffer_full() {
        let e: Error<IoStub> = Error::ReceiveBufferFull;
        assert_eq!(show(&e), "receive buffer full");
    }

    #[test]
    fn error_display_logcat_uses_inner_unprefixed() {
        let e: Error<IoStub> = Error::Logcat(LogcatError::InvalidHeader);
        assert_eq!(show(&e), "logcat: invalid logger_entry header");
    }

    #[test]
    fn error_display_decode_uses_inner_unprefixed() {
        let e: Error<IoStub> = Error::Decode(DecodeError::InvalidProtobuf);
        assert_eq!(show(&e), "invalid protobuf");
    }

    #[test]
    fn error_display_missing_feature_lists_debug_and_wire_name() {
        let e: Error<IoStub> = Error::MissingFeature(Feature::ShellV2);
        assert_eq!(
            show(&e),
            "device does not advertise feature ShellV2 (shell_v2)"
        );
    }

    #[test]
    fn error_and_inner_enums_implement_core_error() {
        fn assert_core_error<E: core::error::Error>(_: &E) {}

        assert_core_error(&Error::<IoStub>::ChannelClosed);
        assert_core_error(&ProtocolError::InvalidMagic);
        assert_core_error(&AuthError::Rejected);
        assert_core_error(&SyncError::RemoteErrno(1));
        assert_core_error(&LogcatError::InvalidHeader);
        assert_core_error(&DecodeError::InvalidProtobuf);
    }

    #[test]
    fn error_source_exposes_inner_error() {
        let e: Error<IoStub> = Error::Protocol(ProtocolError::InvalidMagic);
        let source = core::error::Error::source(&e).expect("protocol source");
        assert_eq!(format!("{source}"), "invalid message magic");

        let io: Error<IoStub> = Error::Io(IoStub);
        let source = core::error::Error::source(&io).expect("io source");
        assert_eq!(format!("{source}"), "io-stub");
    }

    #[test]
    fn error_source_is_none_for_leaf_variants() {
        assert!(core::error::Error::source(&Error::<IoStub>::ChannelClosed).is_none());
        assert!(core::error::Error::source(&Error::<IoStub>::UnexpectedEof).is_none());
    }

    #[test]
    fn error_from_protocol_wraps_into_protocol_variant() {
        let e: Error<IoStub> = ProtocolError::InvalidMagic.into();
        assert!(matches!(e, Error::Protocol(ProtocolError::InvalidMagic)));
    }

    #[test]
    fn error_from_auth_wraps_into_auth_variant() {
        let e: Error<IoStub> = AuthError::Rejected.into();
        assert!(matches!(e, Error::Auth(AuthError::Rejected)));
    }

    #[test]
    fn error_from_sync_wraps_into_sync_variant() {
        let e: Error<IoStub> = SyncError::RemoteErrno(5).into();
        assert!(matches!(e, Error::Sync(SyncError::RemoteErrno(5))));
    }

    #[test]
    fn error_from_logcat_wraps_into_logcat_variant() {
        let e: Error<IoStub> = LogcatError::InvalidHeader.into();
        assert!(matches!(e, Error::Logcat(LogcatError::InvalidHeader)));
    }

    #[test]
    fn error_from_decode_wraps_into_decode_variant() {
        let e: Error<IoStub> = DecodeError::InvalidUtf8.into();
        assert!(matches!(e, Error::Decode(DecodeError::InvalidUtf8)));
    }
}
