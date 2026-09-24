use alloc::ffi::CString;
use alloc::format;
use core::cell::RefCell;
use core::ffi::c_char;

use libadb::base::error::{Error, ProtocolError, ReverseError};
#[cfg(feature = "pairing")]
use libadb::pairing::{AeadError, PairingError};

use crate::transport::FfiConnectError;

/// Status code returned by most FFI entry points.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdbStatus {
    Ok = 0,
    InvalidArg = 1,
    InvalidUri = 2,
    Connect = 3,
    Io = 4,
    Auth = 5,
    Protocol = 6,
    ChannelClosed = 7,
    NoFreeChannels = 8,
    Desynchronized = 9,
    /// The device's reverse rule service refused the request; the
    /// device's own message is in [`adb_last_error`].
    Reverse = 10,
    /// The device answered the handshake with `STLS` (Android 11+
    /// wireless debugging) and this call cannot start TLS: the library
    /// was built without the `tls` feature, or the key sits behind an
    /// [`adb_authenticator_t`](crate::adb_authenticator_t). The message
    /// says which.
    TlsRequired = 11,
    /// `adb_pair`: the device did not take the key. The code did not
    /// match, or the device ended the exchange itself (dialog
    /// dismissed, attempts used up); [`adb_last_error`] says which.
    Pairing = 12,
    Internal = 255,
}

/// The core's advice names `Connection::connect_tls`, which a C caller
/// cannot follow; this is the advice that applies to the C API.
#[cfg(not(feature = "tls"))]
const TLS_REQUIRED: &str = "device requires TLS (Android 11+ wireless debugging): \
    build libadb-ffi with the `tls` feature, connect over USB, \
    or switch the device to plain TCP with `adb tcpip 5555`";
#[cfg(feature = "tls")]
const TLS_REQUIRED: &str = "device requires TLS (Android 11+ wireless debugging), \
    which only adb_connect with the private key can start: \
    adb_connect_with_authenticator stays in the clear";

std::thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set(msg: impl core::fmt::Display) {
    let s = format!("{msg}").replace('\0', " ");
    let c = CString::new(s).unwrap_or_else(|_| CString::new("<error>").unwrap());
    LAST_ERROR.with(|l| *l.borrow_mut() = Some(c));
}

pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|l| *l.borrow_mut() = None);
}

pub(crate) fn fail_invalid_arg(msg: impl core::fmt::Display) -> AdbStatus {
    set(msg);
    AdbStatus::InvalidArg
}

pub(crate) fn fail_io(msg: impl core::fmt::Display) -> AdbStatus {
    set(msg);
    AdbStatus::Io
}

pub(crate) fn fail_auth(msg: impl core::fmt::Display) -> AdbStatus {
    set(msg);
    AdbStatus::Auth
}

pub(crate) fn fail_internal(msg: impl core::fmt::Display) -> AdbStatus {
    set(msg);
    AdbStatus::Internal
}

#[cfg(feature = "pairing")]
pub(crate) fn fail_invalid_uri(msg: impl core::fmt::Display) -> AdbStatus {
    set(msg);
    AdbStatus::InvalidUri
}

/// The verdict on a pairing that did not end with the key on the
/// device.
#[cfg(feature = "pairing")]
pub(crate) fn fail_pairing(e: PairingError<std::io::Error>) -> AdbStatus {
    let status = match &e {
        // The device's block arrived and did not open: the code did
        // not match.
        PairingError::WrongCode => AdbStatus::Pairing,
        // EOF mid-exchange is the device ending it — dialog dismissed,
        // attempts used up — a verdict, not a network fault that a
        // retry would cure.
        PairingError::Closed => AdbStatus::Pairing,
        // `pair` folds this into `WrongCode` today; kept for the day
        // it does not.
        PairingError::Aead(AeadError::Decrypt) => AdbStatus::Pairing,
        // Our own cipher failing on our own side.
        PairingError::Aead(_) => AdbStatus::Internal,
        PairingError::Transport(_) => AdbStatus::Io,
        PairingError::Frame(_) | PairingError::Spake2(_) | PairingError::PeerInfo(_) => {
            AdbStatus::Protocol
        }
        _ => AdbStatus::Internal,
    };
    set(e);
    status
}

pub(crate) fn fail_ffi_connect(e: FfiConnectError) -> AdbStatus {
    let status = match &e {
        FfiConnectError::Uri(_) => AdbStatus::InvalidUri,
        _ => AdbStatus::Connect,
    };
    set(e);
    status
}

pub(crate) fn fail_error<E: core::fmt::Display>(e: Error<E>) -> AdbStatus {
    let status = match &e {
        Error::Protocol(ProtocolError::TlsRequired) => {
            set(TLS_REQUIRED);
            return AdbStatus::TlsRequired;
        }
        Error::Io(_) | Error::UnexpectedEof => AdbStatus::Io,
        Error::Auth(_) => AdbStatus::Auth,
        Error::Protocol(_) => AdbStatus::Protocol,
        Error::ChannelClosed => AdbStatus::ChannelClosed,
        Error::NoFreeChannels => AdbStatus::NoFreeChannels,
        Error::Desynchronized => AdbStatus::Desynchronized,
        // The device refused the rule — an answer, not a breakage; a
        // malformed reply is a protocol fault like any other.
        Error::Reverse(ReverseError::Failed(_)) => AdbStatus::Reverse,
        Error::Reverse(ReverseError::UnexpectedReply) => AdbStatus::Protocol,
        _ => AdbStatus::Internal,
    };
    set(e);
    status
}

/// Return a pointer to a C string describing the last error that
/// occurred on this thread, or NULL if no error is set.
///
/// The pointer is valid until the next FFI call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn adb_last_error() -> *const c_char {
    LAST_ERROR.with(|l| match &*l.borrow() {
        Some(c) => c.as_ptr(),
        None => core::ptr::null(),
    })
}
