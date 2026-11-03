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

mod auth;
mod block_on;
mod connection;
mod error;
mod feature;
mod keys;
#[macro_use]
mod macros;
#[cfg(feature = "pairing")]
mod pairing;
mod shell;
mod slice;
mod transport;

use core::ffi::{c_char, CStr};
use core::ptr;

use libadb::base::channel::ChannelId;
use libadb::reverse;

use connection::lock_poisoned;

pub use auth::{adb_authenticator_t, AdbSignFn};
// Also reachable through the C ABI; re-exported so Rust consumers of the
// rlib — the crate's own integration tests among them — can name them.
pub use connection::{
    adb_connect, adb_connect_with_authenticator, adb_connection_delayed_ack,
    adb_connection_device_banner, adb_connection_free, adb_connection_max_payload,
    adb_connection_set_io_timeout_ms, adb_connection_t,
};
pub use error::{adb_last_error, AdbStatus};
pub use keys::{
    adb_key_free, adb_key_load_or_generate, adb_key_private_key_pem, adb_key_public_key, adb_key_t,
};
#[cfg(feature = "pairing")]
pub use pairing::adb_pair;
pub use shell::{
    adb_shell_close, adb_shell_close_stdin, adb_shell_free, adb_shell_open, adb_shell_read_frame,
    adb_shell_set_window_size, adb_shell_t, adb_shell_write_stdin,
};

fn encode_channel_id(ch: ChannelId) -> u64 {
    ((ch.local_id() as u64) << 32) | (ch.slot() as u32 as u64)
}

fn decode_channel_id(id: u64) -> ChannelId {
    ChannelId::from_raw((id & 0xFFFF_FFFF) as u32 as usize, (id >> 32) as u32)
}

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

/// Open a new channel to `destination`.
///
/// `destination` is an ADB service string, e.g. `"shell:ls"`,
/// `"tcp:8080"`, `"sync:"`. It does not need to be null-terminated.
/// On success, `*out_id` receives a 64-bit channel ID (packed slot +
/// wire local_id) usable with the other `adb_*_channel` functions
/// until it is closed. A channel ID from a closed channel is stale:
/// calls against it fail with [`AdbStatus::ChannelClosed`] even if
/// the slot has since been reused for a new channel.
///
/// # Safety
/// `conn` must be a valid handle. `destination` must be NULL or point
/// to at least `destination_len` readable bytes. `out_id` must point
/// to a writable `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_open_channel(
    conn: *mut adb_connection_t,
    destination: *const u8,
    destination_len: usize,
    out_id: *mut u64,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_id.is_null() || (destination.is_null() && destination_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    let dest = slice::from_ptr(destination, destination_len);
    let mut g = (*conn).lock_reader();
    let id = ffi_try!(g.open_channel(dest));
    *out_id = encode_channel_id(id);
    AdbStatus::Ok
}

/// Read from a channel into `buf` (up to `buf_len` bytes). Writes the
/// number of bytes actually read through `out_read`.
///
/// A return of `ADB_OK` with `*out_read == 0` never occurs; channel
/// closure is reported as [`AdbStatus::ChannelClosed`]. That is what
/// makes `while (adb_read_channel(...) == ADB_OK)` a correct loop, so
/// `buf_len == 0` is rejected with [`AdbStatus::InvalidArg`] rather
/// than answering with a zero that the loop would spin on, and a
/// zero-length WRTE from the device — legal, and delivering nothing —
/// is read past instead of surfacing as that same zero.
///
/// # Safety
/// `conn` must be a valid handle. `buf` must be NULL or point to at
/// least `buf_len` writable bytes. `out_read` must point to a
/// writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_read_channel(
    conn: *mut adb_connection_t,
    id: u64,
    buf: *mut u8,
    buf_len: usize,
    out_read: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_read.is_null() || (buf.is_null() && buf_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    if buf_len == 0 {
        return error::fail_invalid_arg("buf_len is zero");
    }
    let slice = slice::from_mut_ptr(buf, buf_len);
    let mut g = (*conn).lock_reader();
    let ch = decode_channel_id(id);
    // The reader hands back Ok(0) for a zero-length WRTE; the C
    // contract above forbids returning it.
    let n = loop {
        let n = ffi_try!(g.read_channel(ch, slice));
        if n > 0 {
            break n;
        }
    };
    *out_read = n;
    AdbStatus::Ok
}

/// Write `buf_len` bytes from `buf` to a channel. Returns only after
/// all bytes have been framed and handed to the transport (chunked to
/// the negotiated `max_payload` and flow-controlled).
///
/// Does not require the reader mutex — safe to call concurrently with
/// [`adb_read_channel`] on another thread.
///
/// # Safety
/// `conn` must be a valid handle. `buf` must be NULL or point to at
/// least `buf_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_write_channel(
    conn: *mut adb_connection_t,
    id: u64,
    buf: *const u8,
    buf_len: usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || (buf.is_null() && buf_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    let slice = slice::from_ptr(buf, buf_len);
    let ch = decode_channel_id(id);
    ffi_try!((*conn).writer.write_channel(ch, slice));
    AdbStatus::Ok
}

/// Close a channel. Subsequent reads/writes against this ID will fail
/// with [`AdbStatus::ChannelClosed`].
///
/// # Safety
/// `conn` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_close_channel(conn: *mut adb_connection_t, id: u64) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    let ch = decode_channel_id(id);
    ffi_try!((*conn).writer.close_channel(ch));
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

/// Establish a reverse forward: the device listens on `device_spec`
/// and opens a channel toward the host for each connection, with
/// `host_spec` as its destination. Receive those channels with
/// [`adb_accept_channel`].
///
/// The service's reply is written to `(data, data_cap, out_data_len)`
/// as [`adb_connection_features`] does — for a `tcp:` device spec it is
/// the bound port in decimal (use `tcp:0` to let the device choose).
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
    let (Ok(device), Ok(host)) = (
        CStr::from_ptr(device_spec).to_str(),
        CStr::from_ptr(host_spec).to_str(),
    ) else {
        return error::fail_invalid_arg("spec is not valid UTF-8");
    };
    let mut g = (*conn).lock_reader();
    let bound = ffi_try!(reverse::establish(&mut *g, device, host));
    copy_out(&bound, data, data_cap, out_data_len);
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
    let Ok(device) = CStr::from_ptr(device_spec).to_str() else {
        return error::fail_invalid_arg("spec is not valid UTF-8");
    };
    let mut g = (*conn).lock_reader();
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
    let mut g = (*conn).lock_reader();
    ffi_try!(reverse::remove_all(&mut *g));
    AdbStatus::Ok
}

/// List the device's reverse rules, as `<serial> <remote> <local>\n`
/// lines, into `(buf, buf_len, out_len)` per [`adb_connection_features`].
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
    let mut g = (*conn).lock_reader();
    let listing = ffi_try!(reverse::list(&mut *g));
    copy_out(&listing, buf, buf_len, out_len);
    AdbStatus::Ok
}

/// Report the staged device-initiated channel (`adb reverse` traffic),
/// waiting for one to arrive if none is staged, and copy its
/// destination into `(dest, dest_cap, out_dest_len)` per
/// [`adb_connection_features`]. The request stays staged on the handle
/// until [`adb_incoming_accept`] or [`adb_incoming_reject`] consumes
/// exactly it — repeated calls report the same request again, which is
/// what makes the truncate-and-report convention usable here: probe
/// with `(NULL, 0, &len)`, allocate, call again for the bytes.
///
/// With nothing staged this blocks until a channel arrives, exactly as
/// [`adb_read_channel`] blocks for data, and — like it — holds the read
/// lock while waiting, so a device that never opens one parks this
/// call. The staged request is held locked for the whole call, so
/// concurrent reports and verdicts serialize against it rather than
/// racing for the queue. There is no way to interrupt it yet; in
/// particular the handle must stay alive until this returns — freeing
/// it from another thread while a call is blocked is undefined
/// behaviour, not an interruption mechanism.
///
/// # Safety
/// `conn` must be a valid handle and must not be freed while this call
/// is in flight. `dest` must be NULL or writable for `dest_cap` bytes;
/// `out_dest_len` must be NULL or a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_accept_channel(
    conn: *mut adb_connection_t,
    dest: *mut u8,
    dest_cap: usize,
    out_dest_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // The staged lock is held across the empty check, the dequeue and
    // the store: concurrent reports serialize on one staged request —
    // a re-report of the same holder, never two racing holders. The
    // reader lock nests inside it, in that order only.
    let mut staged = lock_poisoned(&(*conn).staged_incoming);
    // A request already staged is re-reported, not displaced — that
    // keeps probe-allocate-copy sequences working on one request.
    if let Some(incoming) = staged.as_ref() {
        copy_out(incoming.destination(), dest, dest_cap, out_dest_len);
        return AdbStatus::Ok;
    }
    let mut g = (*conn).lock_reader();
    let incoming = ffi_try!(g.accept_incoming());
    drop(g);
    copy_out(incoming.destination(), dest, dest_cap, out_dest_len);
    // Stage the request itself: the verdict calls consume it, so they
    // cannot answer some other OPEN that queued up in the meantime.
    *staged = Some(incoming);
    AdbStatus::Ok
}

/// Accept the channel staged by [`adb_accept_channel`], returning its
/// ID through `out_id`.
///
/// # Safety
/// `conn` must be a valid handle; `out_id` a writable `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_incoming_accept(
    conn: *mut adb_connection_t,
    out_id: *mut u64,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_id.is_null() {
        return error::fail_invalid_arg("null pointer");
    }
    let staged = lock_poisoned(&(*conn).staged_incoming).take();
    let Some(incoming) = staged else {
        return error::fail_invalid_arg("no incoming channel is staged");
    };
    let ch = ffi_try!(incoming.accept());
    *out_id = encode_channel_id(ch);
    AdbStatus::Ok
}

/// Reject the channel staged by [`adb_accept_channel`].
///
/// # Safety
/// `conn` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_incoming_reject(conn: *mut adb_connection_t) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    let staged = lock_poisoned(&(*conn).staged_incoming).take();
    let Some(incoming) = staged else {
        return error::fail_invalid_arg("no incoming channel is staged");
    };
    ffi_try!(incoming.reject());
    AdbStatus::Ok
}
