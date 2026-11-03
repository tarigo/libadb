//! `adb reverse` rules: establishing, removing and listing them.

use core::ffi::{c_char, CStr};

use libadb::reverse;

use crate::connection::adb_connection_t;
use crate::error::{self, AdbStatus};
use crate::slice::copy_out;

/// Establish a reverse forward: the device listens on `device_spec`
/// and opens a channel toward the host for each connection, with
/// `host_spec` as its destination. Receive those channels with
/// [`adb_accept_channel`].
///
/// The service's reply is written to `(data, data_cap, out_data_len)`
/// as [`adb_connection_features`] does — for a `tcp:` device spec it is
/// the bound port in decimal (use `tcp:0` to let the device choose).
///
/// [`adb_accept_channel`]: crate::adb_accept_channel
/// [`adb_connection_features`]: crate::adb_connection_features
///
/// # Safety
/// `conn` must be a valid handle. `device_spec`/`host_spec` must be
/// NUL-terminated C strings. `data` must be NULL or writable for
/// `data_cap` bytes; `out_data_len` must be NULL or a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_reverse_forward(
    conn: *mut adb_connection_t,
    device_spec: *const c_char,
    host_spec: *const c_char,
    data: *mut u8,
    data_cap: usize,
    out_data_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || device_spec.is_null() || host_spec.is_null() {
        return error::fail_invalid_arg("null pointer");
    }
    // SAFETY: both are non-null, and C strings per `# Safety`.
    let (device, host) = unsafe { (CStr::from_ptr(device_spec), CStr::from_ptr(host_spec)) };
    let (Ok(device), Ok(host)) = (device.to_str(), host.to_str()) else {
        return error::fail_invalid_arg("spec is not valid UTF-8");
    };
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let mut g = unsafe { &*conn }.lock_reader();
    let bound = ffi_try!(reverse::establish(&mut *g, device, host));
    // SAFETY: `data` and `out_data_len` are NULL or writable as sized, per `# Safety`.
    unsafe { copy_out(&bound, data, data_cap, out_data_len) };
    AdbStatus::Ok
}

/// Remove the reverse rule listening on `device_spec`.
///
/// # Safety
/// `conn` must be a valid handle; `device_spec` a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_reverse_remove(
    conn: *mut adb_connection_t,
    device_spec: *const c_char,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || device_spec.is_null() {
        return error::fail_invalid_arg("null pointer");
    }
    // SAFETY: non-null, and a C string per `# Safety`.
    let Ok(device) = unsafe { CStr::from_ptr(device_spec) }.to_str() else {
        return error::fail_invalid_arg("spec is not valid UTF-8");
    };
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let mut g = unsafe { &*conn }.lock_reader();
    ffi_try!(reverse::remove(&mut *g, device));
    AdbStatus::Ok
}

/// Remove every reverse rule this connection established.
///
/// # Safety
/// `conn` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_reverse_remove_all(conn: *mut adb_connection_t) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let mut g = unsafe { &*conn }.lock_reader();
    ffi_try!(reverse::remove_all(&mut *g));
    AdbStatus::Ok
}

/// List the device's reverse rules, as `<serial> <remote> <local>\n`
/// lines, into `(buf, buf_len, out_len)` per [`adb_connection_features`].
///
/// [`adb_connection_features`]: crate::adb_connection_features
///
/// # Safety
/// `conn` must be a valid handle. `buf` must be NULL or writable for
/// `buf_len` bytes; `out_len` must be NULL or a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_reverse_list(
    conn: *mut adb_connection_t,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let mut g = unsafe { &*conn }.lock_reader();
    let listing = ffi_try!(reverse::list(&mut *g));
    // SAFETY: `buf` and `out_len` are NULL or writable as sized, per `# Safety`.
    unsafe { copy_out(&listing, buf, buf_len, out_len) };
    AdbStatus::Ok
}
