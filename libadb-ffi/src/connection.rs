//! The connection handle: opening it, its socket timeouts, what the
//! handshake negotiated, and releasing it.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, CStr};
use std::sync::Mutex;

use libadb::base::auth::Authenticator;
use libadb::base::connection::{Connection, ConnectionConfig, HostBanner};
use libadb::split::{Reader, SplitIncoming, Writer};
use libadb::Splittable;

use crate::auth::{self, adb_authenticator_t};
use crate::block_on;
use crate::error::{self, AdbStatus};
use crate::slice::copy_out;
use crate::transport::{self, FfiTransport};

// The halves a connection splits into: under TLS they are not the
// transport itself.
pub(crate) type FfiReadHalf = <FfiTransport as Splittable>::ReadHalf;
pub(crate) type FfiWriteHalf = <FfiTransport as Splittable>::WriteHalf;
pub(crate) type FfiReader = Reader<FfiReadHalf, FfiWriteHalf>;
pub(crate) type FfiWriter = Writer<FfiWriteHalf>;
pub(crate) type FfiIncoming = SplitIncoming<FfiWriteHalf>;

/// Opaque connection handle.
///
/// Holds a split Reader + Writer pair. The Reader sits behind a mutex
/// so that multiple C threads can share a handle safely. A write does
/// not wait for that mutex, but takes it when it finds it free and has
/// to wait for the device: see the [crate docs](crate).
#[allow(non_camel_case_types)]
pub struct adb_connection_t {
    pub(crate) reader: Arc<Mutex<FfiReader>>,
    pub(crate) writer: FfiWriter,
    /// Second handle to the TCP socket for timeouts; None over USB.
    pub(crate) tcp_socket: Option<std::net::TcpStream>,
    /// The device-initiated OPEN that [`adb_accept_channel`] reported.
    /// It stays here, and repeated calls report it again, until
    /// [`adb_incoming_accept`] or [`adb_incoming_reject`] takes it out.
    ///
    /// [`adb_accept_channel`]: crate::adb_accept_channel
    /// [`adb_incoming_accept`]: crate::adb_incoming_accept
    /// [`adb_incoming_reject`]: crate::adb_incoming_reject
    pub(crate) staged_incoming: Mutex<Option<FfiIncoming>>,
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
/// On success `*out` is set to a freshly-allocated handle that must be
/// released with [`adb_connection_free`].
///
/// With the `tls` feature this answers a wireless-debugging device's
/// `STLS`; without it such a device is [`AdbStatus::TlsRequired`]. As
/// with `adb`, the device is not authenticated. See `libadb.h`.
///
/// # Safety
/// `uri`, `priv_key_pem`, `pub_key` and `banner` must be valid
/// null-terminated C strings. `out` must point to a writable
/// `adb_connection_t*`.
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

    // SAFETY: all four are non-null, and C strings per `# Safety`.
    let (uri, priv_key_pem, pub_key, banner) = unsafe {
        (
            CStr::from_ptr(uri),
            CStr::from_ptr(priv_key_pem),
            CStr::from_ptr(pub_key),
            CStr::from_ptr(banner),
        )
    };
    let uri = match uri.to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let priv_pem = match priv_key_pem.to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let pub_key_bytes = pub_key.to_bytes();
    let banner_bytes = banner.to_bytes();

    let auth = match auth::FfiAuthenticator::from_pkcs8_pem(priv_pem, pub_key_bytes) {
        Ok(a) => a,
        Err(e) => return error::fail_auth(e),
    };

    // SAFETY: `out` is non-null and writable, per `# Safety`.
    unsafe { handshake(uri, out, |t| connect_with_key(t, auth, banner_bytes)) }
}

/// Like [`adb_connect`], but uses a caller-supplied [`adb_authenticator_t`]
/// instead of the built-in RSA/PEM authenticator, for a private key that
/// lives outside the host process.
///
/// Plaintext only: against a wireless-debugging port this call is
/// [`AdbStatus::TlsRequired`] whatever the build. See `libadb.h`.
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

    // SAFETY: both are non-null, and C strings per `# Safety`.
    let (uri, banner) = unsafe { (CStr::from_ptr(uri), CStr::from_ptr(banner)) };
    let uri = match uri.to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let banner_bytes = banner.to_bytes();

    // SAFETY: non-null, and valid with a readable key and a live callback per `# Safety`.
    let auth = match unsafe { auth::CallbackAuthenticator::from_ffi(&*authenticator) } {
        Ok(a) => a,
        Err(e) => return error::fail_invalid_arg(e),
    };

    // SAFETY: `out` is non-null and writable, per `# Safety`.
    unsafe { handshake(uri, out, |t| connect_plain(t, auth, banner_bytes)) }
}

/// Open `uri`, run `connect` over the transport, and box the split
/// result into a handle.
///
/// # Safety
/// `out` must point to a writable `adb_connection_t*`.
unsafe fn handshake(
    uri: &str,
    out: *mut *mut adb_connection_t,
    connect: impl FnOnce(FfiTransport) -> Result<Connection<FfiTransport>, AdbStatus>,
) -> AdbStatus {
    let (t, tcp_socket) = match transport::connect(uri) {
        Ok(opened) => opened,
        Err(e) => return error::fail_ffi_connect(e),
    };

    let conn = match connect(t) {
        Ok(c) => c,
        Err(status) => return status,
    };

    let (reader, writer) = match conn.split() {
        Ok(pair) => pair,
        Err(e) => return error::fail_error(e),
    };

    let boxed = Box::new(adb_connection_t {
        reader: Arc::new(Mutex::new(reader)),
        writer,
        tcp_socket,
        staged_incoming: Mutex::new(None),
    });
    // SAFETY: writable, per `# Safety`.
    unsafe { *out = Box::into_raw(boxed) };
    AdbStatus::Ok
}

/// The handshake in the clear.
fn connect_plain<A: Authenticator>(
    t: FfiTransport,
    auth: A,
    banner: &[u8],
) -> Result<Connection<FfiTransport>, AdbStatus> {
    block_on::block_on(Connection::connect(
        t,
        auth,
        HostBanner::Raw(banner),
        ConnectionConfig::new(),
    ))
    .map_err(error::fail_error)
}

/// What `adb_connect` runs: TLS if a TCP device asks for it. adbd never
/// offers STLS over USB, and the certificate costs an RSA signature, so
/// only a `tcp://` connect pays for it.
#[cfg(feature = "tls")]
fn connect_with_key(
    t: FfiTransport,
    auth: auth::FfiAuthenticator,
    banner: &[u8],
) -> Result<Connection<FfiTransport>, AdbStatus> {
    match t {
        FfiTransport::Tcp(_) => {
            let tls = auth.tls_config().map_err(error::fail_internal)?;
            block_on::block_on(Connection::connect_tls(
                t,
                auth,
                HostBanner::Raw(banner),
                ConnectionConfig::new(),
                &tls,
            ))
            .map_err(error::fail_error)
        }
        FfiTransport::Usb(_) => connect_plain(t, auth, banner),
    }
}

#[cfg(not(feature = "tls"))]
fn connect_with_key(
    t: FfiTransport,
    auth: auth::FfiAuthenticator,
    banner: &[u8],
) -> Result<Connection<FfiTransport>, AdbStatus> {
    connect_plain(t, auth, banner)
}

/// Set the receive and send timeouts of a `tcp://` connection, in
/// milliseconds; 0 disables that timeout. USB transports answer
/// [`AdbStatus::InvalidArg`].
///
/// A read timeout fails the read with [`AdbStatus::Io`] and, on Unix,
/// leaves the connection usable. A write timeout can leave the
/// connection [`AdbStatus::Desynchronized`]. See `libadb.h`.
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
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    let Some(socket) = &conn.tcp_socket else {
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

/// Release a handle from [`adb_connect`] or
/// [`adb_connect_with_authenticator`]. NULL is a no-op.
///
/// # Safety
/// `conn` must be NULL or a handle returned by one of those calls that
/// has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_free(conn: *mut adb_connection_t) {
    if conn.is_null() {
        return;
    }
    // SAFETY: a live handle from `handshake`, which boxed it, per `# Safety`.
    drop(unsafe { Box::from_raw(conn) });
}

/// Negotiated maximum payload size, in bytes; 0 if `conn` is NULL.
///
/// # Safety
/// `conn` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_max_payload(conn: *const adb_connection_t) -> u32 {
    if conn.is_null() {
        return 0;
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    unsafe { &*conn }.writer.max_payload()
}

/// Whether delayed-ACK (credit-based flow control) was negotiated;
/// `false` if `conn` is NULL.
///
/// # Safety
/// `conn` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_delayed_ack(conn: *const adb_connection_t) -> bool {
    if conn.is_null() {
        return false;
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    unsafe { &*conn }.writer.delayed_ack()
}

/// Copy the device banner bytes into `buf` (up to `buf_len` bytes) and
/// write the full banner length through `out_len`, so a caller whose
/// buffer was too short can retry with a larger one.
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
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let banner = unsafe { &*conn }.writer.device_banner();
    // SAFETY: `buf` and `out_len` are NULL or writable as sized, per
    // `# Safety`, and `buf` cannot overlap the handle's own banner.
    unsafe { copy_out(banner, buf, buf_len, out_len) };
    AdbStatus::Ok
}
