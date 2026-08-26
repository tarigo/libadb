use alloc::ffi::CString;
use alloc::format;
use core::cell::RefCell;
use core::ffi::c_char;

use libadb::base::error::Error;

use crate::transport::FfiConnectError;

/// Status code returned by most FFI entry points.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Internal = 255,
}

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
        Error::Io(_) | Error::UnexpectedEof => AdbStatus::Io,
        Error::Auth(_) => AdbStatus::Auth,
        Error::Protocol(_) => AdbStatus::Protocol,
        Error::ChannelClosed => AdbStatus::ChannelClosed,
        Error::NoFreeChannels => AdbStatus::NoFreeChannels,
        Error::Desynchronized => AdbStatus::Desynchronized,
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
