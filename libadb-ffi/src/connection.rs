//! The connection handle: opening it, its socket timeouts, what the
//! handshake negotiated, and releasing it.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, CStr};
use core::ptr;
use std::sync::Mutex;

use libadb::base::auth::Authenticator;
use libadb::base::connection::{Connection, ConnectionConfig, HostBanner};
use libadb::split::{Reader, SplitIncoming, Writer};
use libadb::Splittable;

use crate::auth::{self, adb_authenticator_t};
use crate::block_on;
use crate::error::{self, AdbStatus};
use crate::transport::{self, FfiTransport};

// The halves a connection splits into: with TLS in the picture they are
// no longer the transport itself.
pub(crate) type FfiReadHalf = <FfiTransport as Splittable>::ReadHalf;
pub(crate) type FfiWriteHalf = <FfiTransport as Splittable>::WriteHalf;
pub(crate) type FfiReader = Reader<FfiReadHalf, FfiWriteHalf>;
pub(crate) type FfiWriter = Writer<FfiWriteHalf>;
pub(crate) type FfiIncoming = SplitIncoming<FfiWriteHalf>;

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
    /// The device-initiated OPEN reported by [`adb_accept_channel`],
    /// staged until a verdict consumes it. Repeated report calls
    /// re-report this holder; only [`adb_incoming_accept`] and
    /// [`adb_incoming_reject`] take it out.
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
/// Wireless debugging (Android 11+): the port the "Wireless debugging"
/// screen shows answers the handshake with `STLS` and speaks TLS 1.3 from
/// then on. Built with the `tls` feature, this call takes that up: it
/// presents a certificate carrying the key in `priv_key_pem`, so a key
/// the device already trusts — confirmed at a USB prompt, or paired —
/// needs nothing more, and one it does not trust is
/// [`AdbStatus::Auth`]. Without the feature the call is
/// [`AdbStatus::TlsRequired`]. The port changes every time the setting
/// is switched on and this library does no DNS-SD, so the caller
/// supplies it. The legacy port `adb tcpip` opens, and USB, stay in the
/// clear either way. A certificate that cannot be built for the key —
/// the system clock outside what a certificate can carry, for one — is
/// [`AdbStatus::Internal`].
///
/// # Security
///
/// As with `adb`, the device is not authenticated. Its certificate is
/// self-signed and taken on trust, and TLS starts only when the device
/// asks for it with `STLS`: a peer that answers CNXN or AUTH instead is
/// served in the clear. On a network you do not trust, an attacker in
/// the middle can therefore take the device's place, inside TLS or, by
/// answering without `STLS`, outside it. TLS keeps a passive
/// eavesdropper out, but this API has no way to pin the device's
/// certificate or to insist on TLS.
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

    handshake(uri, out, |t| connect_with_key(t, auth, banner_bytes))
}

/// Like [`adb_connect`], but uses a caller-supplied [`adb_authenticator_t`]
/// instead of the built-in RSA/PEM authenticator.
///
/// Use this when the private key lives outside the host process — e.g.
/// in an HSM, a remote signing service, or a non-PKCS#8 key store. The
/// [`sign`](adb_authenticator_t::sign) callback runs synchronously
/// during the handshake.
///
/// Plaintext only: the callback signs the 20-byte AUTH token, while TLS
/// 1.3 client authentication needs an RSA-PSS signature over the
/// handshake transcript and a certificate, neither of which it can
/// produce. Against a wireless-debugging port this call is
/// [`AdbStatus::TlsRequired`] whatever the build; use [`adb_connect`]
/// with the private key there.
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

    handshake(uri, out, |t| connect_plain(t, auth, banner_bytes))
}

/// Open `uri`, run `connect` over the transport, and box the split
/// result into a handle.
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
    *out = Box::into_raw(boxed);
    AdbStatus::Ok
}

/// The plain handshake, as every connect ran it before `tls`.
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
/// Both hold on a TLS (wireless-debugging) connection too: the timeouts
/// sit on the socket underneath, a timed-out read leaves the session
/// and the partial packet intact, and a timed-out write is the same
/// abandoned packet.
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
/// [`adb_read_channel`]: crate::adb_read_channel
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
