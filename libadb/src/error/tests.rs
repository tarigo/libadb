use super::{AuthError, DecodeError, Error, ProtocolError, SyncError};
use crate::base::protocol::features::Feature;
use crate::base::protocol::Command;
use crate::logcat::LogcatError;
use crate::sync::SyncFlags;
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
fn protocol_display_tls_required_names_a_way_out() {
    assert_eq!(
        show(&ProtocolError::TlsRequired),
        "device requires a TLS handshake (Android 11+ wireless debugging) \
         that this connection does not do; connect over USB, \
         or switch the device to plain TCP with `adb tcpip 5555`"
    );
}

#[test]
fn protocol_display_data_after_stls() {
    assert_eq!(
        show(&ProtocolError::DataAfterStls),
        "device sent more in the clear after STLS, where only TLS may follow"
    );
}

#[test]
fn auth_display_tls_key_not_trusted_points_at_pairing() {
    assert_eq!(
        show(&AuthError::TlsKeyNotTrusted),
        "device does not trust this key over TLS; authorise it over USB or run `adb pair`"
    );
}

#[test]
fn auth_display_tls_closed_before_connect_points_at_pairing_only_if_it_applies() {
    assert_eq!(
        show(&AuthError::TlsClosedBeforeConnect),
        "device closed the TLS session right after the handshake, before its CNXN; \
         if this key was never paired or authorised, run `adb pair` or authorise it over USB"
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
}

#[test]
fn auth_display_rejected_and_sign_failed() {
    assert_eq!(show(&AuthError::Rejected), "authentication rejected");
    assert_eq!(
        show(&AuthError::SignFailed(alloc::string::String::from(
            "no key"
        ))),
        "authenticator sign failed: no key"
    );
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
fn sync_display_invalid_flags_gives_the_bits() {
    let flags = SyncFlags::BROTLI | SyncFlags::DRY_RUN;
    assert_eq!(
        show(&SyncError::InvalidFlags(flags)),
        "sync: invalid flags 0x80000001"
    );
}

#[test]
fn sync_display_invalid_path() {
    assert_eq!(
        show(&SyncError::InvalidPath),
        "sync: path contains a NUL byte"
    );
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
fn logcat_display_exited_shows_only_the_line_with_the_reason() {
    // logcat warns before its reason and may explain after it.
    let stderr = b"WARNING: -T 0 invalid, setting to 1\n\
                   logcat: Unexpected EOF!\n\
                   \n\
                   If you have enabled significant logging, look into using the -G option.\n";
    let e = LogcatError::Exited {
        code: 1,
        stderr: stderr.to_vec(),
    };
    assert_eq!(
        show(&e),
        "logcat exited with status 1: logcat: Unexpected EOF!"
    );
}

#[test]
fn logcat_display_closed_without_exit() {
    assert_eq!(
        show(&LogcatError::ClosedWithoutExit),
        "logcat's channel closed before its exit status arrived"
    );
}

#[test]
fn logcat_display_truncated_entry() {
    assert_eq!(
        show(&LogcatError::TruncatedEntry),
        "logcat's output ended in the middle of an entry"
    );
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
