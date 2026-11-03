//! C ABI for [`libadb`].
//!
//! The API is synchronous from the caller's perspective: each async
//! operation is driven to completion by a tiny internal executor. No
//! tokio or smol runtime is required.
//!
//! Under the hood a handle is a split [`Reader`] / [`Writer`] pair
//! sharing a reference-counted state. The read-path and the write-path
//! never take the same mutex at the same time, so a thread blocked in
//! a long read does not prevent another thread from writing — which is
//! what makes interactive shell sessions usable from C without any
//! async runtime.
//!
//! # Feature flags
//!
//! TCP support is always compiled in and needs no async runtime. USB
//! support is opt-in: enable `usb` (alias for the pure-Rust `nusb`
//! backend) or `rusb` (libusb); the two backends are mutually
//! exclusive.
//!
//! `tls` answers a wireless-debugging device's `STLS` (Android 11+)
//! from [`adb_connect`] with TLS 1.3, presenting the caller's key in a
//! certificate; without it such a device is [`AdbStatus::TlsRequired`].
//! [`adb_connect_with_authenticator`] stays in the clear either way.
//!
//! `pairing` (implies `tls`) adds `adb_pair`, the `adb pair` exchange
//! against the device's pairing dialog: the one way to put a key on a
//! device that has never seen it without a USB cable.
//!
//! [`Reader`]: libadb::Reader
//! [`Writer`]: libadb::Writer

#![no_std]
#![allow(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
extern crate std;

// First: `ffi_try!` is in scope only in the modules declared after it.
#[macro_use]
mod macros;

mod auth;
mod block_on;
mod channel;
mod connection;
mod error;
mod feature;
mod incoming;
mod keys;
#[cfg(feature = "pairing")]
mod pairing;
mod reverse;
mod shell;
mod slice;
mod transport;

use core::ffi::c_char;
use core::ptr;

pub use auth::{adb_authenticator_t, AdbSignFn};
// Also reachable through the C ABI; re-exported so Rust consumers of the
// rlib — the crate's own integration tests among them — can name them.
pub use channel::{adb_close_channel, adb_open_channel, adb_read_channel, adb_write_channel};
pub use connection::{
    adb_connect, adb_connect_with_authenticator, adb_connection_delayed_ack,
    adb_connection_device_banner, adb_connection_free, adb_connection_max_payload,
    adb_connection_set_io_timeout_ms, adb_connection_t,
};
pub use error::{adb_last_error, AdbStatus};
pub use incoming::{adb_accept_channel, adb_incoming_accept, adb_incoming_reject};
pub use keys::{
    adb_key_free, adb_key_load_or_generate, adb_key_private_key_pem, adb_key_public_key, adb_key_t,
};
#[cfg(feature = "pairing")]
pub use pairing::adb_pair;
pub use reverse::{
    adb_reverse_forward, adb_reverse_list, adb_reverse_remove, adb_reverse_remove_all,
};
pub use shell::{
    adb_shell_close, adb_shell_close_stdin, adb_shell_free, adb_shell_open, adb_shell_read_frame,
    adb_shell_set_window_size, adb_shell_t, adb_shell_write_stdin,
};

/// Whether the device advertises `feature`.
///
/// Returns `false` if `conn` is NULL, if the handshake did not
/// produce a parseable banner, or if `feature` is not one of the
/// `ADB_FEATURE_*` constants defined in `libadb.h`.
///
/// Does not take the read lock — safe to call while another thread is
/// blocked in [`adb_read_channel`].
///
/// # Safety
/// `conn` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_has_feature(
    conn: *const adb_connection_t,
    feature: u32,
) -> bool {
    if conn.is_null() {
        return false;
    }
    let Some(ff) = feature::FfiFeature::from_raw(feature) else {
        return false;
    };
    (*conn)
        .writer
        .device_banner_parsed()
        .is_some_and(|b| b.has_feature(&ff.to_feature()))
}

/// Wire-format name of `feature` (e.g. `"shell_v2"`) as a static
/// NUL-terminated string, or NULL if `feature` is not one of the
/// `ADB_FEATURE_*` constants defined in `libadb.h`.
#[unsafe(no_mangle)]
pub extern "C" fn adb_feature_name(feature: u32) -> *const c_char {
    match feature::FfiFeature::from_raw(feature) {
        Some(f) => f.wire_name(),
        None => ptr::null(),
    }
}

/// Copy up to `buf_cap` features advertised by the device into
/// `buf` (in handshake order) and write the full count through
/// `out_len`. Either pointer may be NULL; pass `(NULL, 0, &n)` to
/// query the count, then call again with a larger buffer.
///
/// Features the library does not recognise are silently skipped at
/// handshake parse time, so the returned count covers only known
/// `ADB_FEATURE_*` values.
///
/// Does not take the read lock — safe to call while another thread is
/// blocked in [`adb_read_channel`].
///
/// # Safety
/// `conn` must be NULL or a valid handle. `buf` must be NULL or
/// point to at least `buf_cap` writable `uint32_t` slots.
/// `out_len` must be NULL or point to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_features(
    conn: *const adb_connection_t,
    buf: *mut u32,
    buf_cap: usize,
    out_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    let features = (*conn)
        .writer
        .device_banner_parsed()
        .map_or(&[][..], |b| b.features());
    if !out_len.is_null() {
        *out_len = features.len();
    }
    if !buf.is_null() && buf_cap > 0 {
        let n = features.len().min(buf_cap);
        for (slot, f) in features.iter().take(n).enumerate() {
            *buf.add(slot) = feature::FfiFeature::from_feature(f) as u32;
        }
    }
    AdbStatus::Ok
}

/// Copy `src` into `(buf, buf_len)`, truncating, and report the full
/// length through `out_len`. The buffer-only conventions match
/// [`adb_connection_features`].
unsafe fn copy_out(src: &[u8], buf: *mut u8, buf_len: usize, out_len: *mut usize) {
    if !out_len.is_null() {
        *out_len = src.len();
    }
    if !buf.is_null() && buf_len > 0 {
        let n = src.len().min(buf_len);
        ptr::copy_nonoverlapping(src.as_ptr(), buf, n);
    }
}
