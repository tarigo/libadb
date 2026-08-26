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
//! [`Reader`]: libadb::Reader
//! [`Writer`]: libadb::Writer

#![no_std]
#![allow(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
extern crate std;

mod auth;
mod block_on;
mod error;
mod feature;
#[macro_use]
mod macros;
mod shell;
mod slice;
mod transport;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, CStr};
use core::ptr;
use std::sync::Mutex;

use libadb::base::auth::Authenticator;
use libadb::base::channel::ChannelId;
use libadb::base::connection::Connection;
use libadb::split::{Reader, Writer};

use transport::FfiTransport;

pub use auth::{adb_authenticator_t, AdbSignFn};
// Also reachable through the C ABI; re-exported so Rust consumers of the
// rlib — the crate's own integration tests among them — can name them.
pub use error::{adb_last_error, AdbStatus};
pub use shell::{
    adb_shell_close, adb_shell_close_stdin, adb_shell_free, adb_shell_open, adb_shell_read_frame,
    adb_shell_set_window_size, adb_shell_t, adb_shell_write_stdin,
};

pub(crate) type FfiReader = Reader<FfiTransport, FfiTransport>;
pub(crate) type FfiWriter = Writer<FfiTransport>;

fn encode_channel_id(ch: ChannelId) -> u64 {
    ((ch.local_id() as u64) << 32) | (ch.slot() as u32 as u64)
}

fn decode_channel_id(id: u64) -> ChannelId {
    ChannelId::from_raw((id & 0xFFFF_FFFF) as u32 as usize, (id >> 32) as u32)
}

/// Opaque connection handle.
///
/// Holds a split Reader + Writer pair. The Reader sits behind a mutex
/// so that multiple C threads can share a handle safely (serialised on
/// the read path). The Writer is cheaply cloneable and the write path
/// only briefly locks an internal write-half mutex, so reads and writes
/// from different threads do not block each other.
#[allow(non_camel_case_types)]
pub struct adb_connection_t {
    pub(crate) reader: Arc<Mutex<FfiReader>>,
    pub(crate) writer: FfiWriter,
    /// Second handle to the TCP socket for timeouts; None over USB.
    pub(crate) tcp_socket: Option<std::net::TcpStream>,
}

pub(crate) fn lock_poisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl adb_connection_t {
    pub(crate) fn lock_reader(&self) -> std::sync::MutexGuard<'_, FfiReader> {
        lock_poisoned(&self.reader)
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<adb_connection_t>();
};

/// Parse `uri`, open a transport, and perform the CNXN/AUTH handshake.
///
/// All arguments are null-terminated C strings:
/// * `uri` — `tcp://HOST:PORT` or `usb://[VID:PID|serial/SERIAL]`
/// * `priv_key_pem` — PKCS#8 PEM-encoded RSA private key (contents of
///   `~/.android/adbkey`)
/// * `pub_key` — ADB-formatted public key blob (contents of
///   `~/.android/adbkey.pub`)
/// * `banner` — identity banner, e.g. `"host::features=shell_v2,delayed_ack"`
///
/// On success `*out` is set to a freshly-allocated handle that must be
/// released with [`adb_connection_free`].
///
/// # Safety
/// All pointers must be valid null-terminated C strings. `out` must
/// point to a writable `adb_connection_t*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connect(
    uri: *const c_char,
    priv_key_pem: *const c_char,
    pub_key: *const c_char,
    banner: *const c_char,
    out: *mut *mut adb_connection_t,
) -> AdbStatus {
    error::clear_last_error();
    if uri.is_null()
        || priv_key_pem.is_null()
        || pub_key.is_null()
        || banner.is_null()
        || out.is_null()
    {
        return error::fail_invalid_arg("null pointer");
    }

    let uri = match CStr::from_ptr(uri).to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let priv_pem = match CStr::from_ptr(priv_key_pem).to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let pub_key_bytes = CStr::from_ptr(pub_key).to_bytes();
    let banner_bytes = CStr::from_ptr(banner).to_bytes();

    let auth = match auth::FfiAuthenticator::from_pkcs8_pem(priv_pem, pub_key_bytes) {
        Ok(a) => a,
        Err(e) => return error::fail_auth(e),
    };

    handshake(uri, auth, banner_bytes, out)
}

/// Like [`adb_connect`], but uses a caller-supplied [`adb_authenticator_t`]
/// instead of the built-in RSA/PEM authenticator.
///
/// Use this when the private key lives outside the host process — e.g.
/// in an HSM, a remote signing service, or a non-PKCS#8 key store. The
/// [`sign`](adb_authenticator_t::sign) callback runs synchronously
/// during the handshake.
///
/// # Safety
/// `uri` and `banner` must be valid null-terminated C strings.
/// `authenticator` must point to a valid [`adb_authenticator_t`] whose
/// `public_key` buffer is readable for `public_key_len` bytes and whose
/// `sign` callback remains valid for the duration of this call. `out`
/// must point to a writable `adb_connection_t*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connect_with_authenticator(
    uri: *const c_char,
    authenticator: *const adb_authenticator_t,
    banner: *const c_char,
    out: *mut *mut adb_connection_t,
) -> AdbStatus {
    error::clear_last_error();
    if uri.is_null() || authenticator.is_null() || banner.is_null() || out.is_null() {
        return error::fail_invalid_arg("null pointer");
    }

    let uri = match CStr::from_ptr(uri).to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let banner_bytes = CStr::from_ptr(banner).to_bytes();

    let auth = match auth::CallbackAuthenticator::from_ffi(&*authenticator) {
        Ok(a) => a,
        Err(e) => return error::fail_invalid_arg(e),
    };

    handshake(uri, auth, banner_bytes, out)
}

unsafe fn handshake<A: Authenticator>(
    uri: &str,
    auth: A,
    banner_bytes: &[u8],
    out: *mut *mut adb_connection_t,
) -> AdbStatus {
    let t = match transport::connect(uri) {
        Ok(t) => t,
        Err(e) => return error::fail_ffi_connect(e),
    };
    let tcp_socket = match transport::tcp_socket_of(&t) {
        Ok(s) => s,
        Err(e) => return error::fail_ffi_connect(transport::FfiConnectError::Tcp(e)),
    };

    let conn = ffi_try!(Connection::connect_with_raw_banner(t, auth, banner_bytes));

    let (reader, writer) = match conn.split() {
        Ok(pair) => pair,
        Err(e) => return error::fail_error(e),
    };

    let boxed = Box::new(adb_connection_t {
        reader: Arc::new(Mutex::new(reader)),
        writer,
        tcp_socket,
    });
    *out = Box::into_raw(boxed);
    AdbStatus::Ok
}

/// Set receive/send timeouts on a `tcp://` connection, in
/// milliseconds; 0 disables the corresponding timeout. USB transports
/// have no such knob and answer [`AdbStatus::InvalidArg`].
///
/// A read that hits the timeout fails with [`AdbStatus::Io`], and the
/// connection stays usable: bytes of a partially received packet are
/// kept, so the next read continues where this one stopped.
///
/// **Platform note.** That recoverable-read guarantee holds on Unix,
/// where `SO_RCVTIMEO` leaves the socket intact. On Windows, Winsock
/// documents a blocking receive that expires under `SO_RCVTIMEO` as
/// leaving the connection in an indeterminate state and advises
/// closing it — so there a timed-out read means close the connection,
/// not read again. Until this path uses a readiness-based deadline on
/// Windows, treat the read timeout as recoverable on Unix only.
///
/// A *write* timeout is a harder stop even on Unix: firing mid-packet
/// abandons a write the device has partially seen, so the connection
/// is marked desynchronized and every later channel operation fails
/// with [`AdbStatus::Desynchronized`] — metadata queries and this
/// setter still answer. Set it only where tearing the connection down
/// beats blocking; for a recoverable bound, use the read timeout.
///
/// # Safety
/// `conn` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_set_io_timeout_ms(
    conn: *mut adb_connection_t,
    read_ms: u32,
    write_ms: u32,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null pointer");
    }
    let Some(socket) = &(*conn).tcp_socket else {
        return error::fail_invalid_arg("timeouts apply to tcp:// transports only");
    };
    let as_duration = |ms: u32| (ms > 0).then(|| std::time::Duration::from_millis(u64::from(ms)));
    if let Err(e) = socket.set_read_timeout(as_duration(read_ms)) {
        return error::fail_io(e);
    }
    if let Err(e) = socket.set_write_timeout(as_duration(write_ms)) {
        return error::fail_io(e);
    }
    AdbStatus::Ok
}

/// Release a handle previously returned by [`adb_connect`].
///
/// Passing NULL is a no-op. Passing any other value that was not
/// obtained from [`adb_connect`] is undefined behaviour.
///
/// # Safety
/// `conn` must be NULL or a handle returned by [`adb_connect`] that
/// has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_free(conn: *mut adb_connection_t) {
    if conn.is_null() {
        return;
    }
    drop(Box::from_raw(conn));
}

/// Negotiated maximum payload size, in bytes.
///
/// Returns 0 if `conn` is NULL.
///
/// # Safety
/// `conn` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_max_payload(conn: *const adb_connection_t) -> u32 {
    if conn.is_null() {
        return 0;
    }
    (*conn).writer.max_payload()
}

/// Whether delayed-ACK (credit-based flow control) was negotiated.
///
/// Returns `false` if `conn` is NULL.
///
/// # Safety
/// `conn` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_delayed_ack(conn: *const adb_connection_t) -> bool {
    if conn.is_null() {
        return false;
    }
    (*conn).writer.delayed_ack()
}

/// Copy the device banner bytes into `buf` (up to `buf_len` bytes) and
/// write the full banner length through `out_len`.
///
/// Returns [`AdbStatus::Ok`] on success. If the banner is longer than
/// `buf_len`, `buf` receives the first `buf_len` bytes and `*out_len`
/// still reflects the full length so the caller can retry with a
/// larger buffer.
///
/// Does not take the read lock — safe to call while another thread is
/// blocked in [`adb_read_channel`].
///
/// # Safety
/// `conn` must be a valid handle. `buf` must be NULL or point to
/// writable memory of at least `buf_len` bytes. `out_len` must be NULL
/// or point to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_device_banner(
    conn: *const adb_connection_t,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    let banner = (*conn).writer.device_banner().unwrap_or(&[]);
    if !out_len.is_null() {
        *out_len = banner.len();
    }
    if !buf.is_null() && buf_len > 0 {
        let n = banner.len().min(buf_len);
        ptr::copy_nonoverlapping(banner.as_ptr(), buf, n);
    }
    AdbStatus::Ok
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
