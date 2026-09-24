//! `adb pair` for C: put the caller's key on a device through its
//! "Pair device with pairing code" dialog.

use alloc::format;
use core::ffi::{c_char, CStr};

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{AdbKey, KeyError};
use libadb::pairing::pair;
use libadb::transport::tls::MaybeTls;
use libadb::uri::{self, Uri};

use crate::error::{self, AdbStatus};
use crate::transport::{self, FfiConnectError};

/// Pair with a device: put the key in `priv_key_pem` into its trusted
/// store through "Pair device with pairing code" on its Wireless
/// debugging screen (SPAKE2 inside TLS, as `adb pair` does). A key the
/// device already trusts — one confirmed at a USB prompt — needs none
/// of this; adbd checks both against the same store.
///
/// * `uri` — `tcp://HOST:PORT`, the *pairing* port shown beside the
///   code. It is not the port the device connects on, it changes each
///   time the dialog opens, and it stops listening once one pairing
///   succeeds. `usb://` is [`AdbStatus::InvalidUri`].
/// * `priv_key_pem` — PKCS#8 PEM RSA private key, as
///   [`adb_connect`](crate::adb_connect) takes it.
/// * `pub_key` — the matching ADB-format public key line. The text
///   after the base64 blob (`user@host`) is the name the device lists
///   this host under. A blob that does not belong to the private key
///   is [`AdbStatus::InvalidArg`].
/// * `code` — what the dialog shows: six digits when typed, or the
///   password a QR code carried. Only emptiness is checked here;
///   validate a typed code yourself, since a wrong one costs the device
///   one of its attempts, and it stops serving after twenty.
/// * `guid`, `guid_cap`, `out_guid_len` — receive the device's GUID,
///   the name it announces its connect port under over DNS-SD, with
///   the truncate-and-report convention of
///   [`adb_connection_features`](crate::adb_connection_features);
///   either pointer may be NULL.
///
/// Returns [`AdbStatus::Ok`] once the device has stored the key,
/// whatever became of the GUID copy: by then the pairing is done and
/// the port is gone, so a short buffer is no reason to fail. From then
/// on the same key connects over TLS through `adb_connect`.
///
/// [`AdbStatus::Pairing`] is the device saying no: the code did not
/// match, or it ended the exchange itself. [`AdbStatus::Connect`]
/// means nothing answered at that address, typically a pairing port
/// that has already closed; [`AdbStatus::Io`] is a connection that
/// broke part way. Blocks until the exchange ends; there is no
/// timeout.
///
/// # Safety
/// The four strings must be valid null-terminated C strings. `guid`
/// must be writable for `guid_cap` bytes when not NULL, and
/// `out_guid_len` must point to a writable `size_t` when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_pair(
    uri: *const c_char,
    priv_key_pem: *const c_char,
    pub_key: *const c_char,
    code: *const c_char,
    guid: *mut u8,
    guid_cap: usize,
    out_guid_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if uri.is_null() || priv_key_pem.is_null() || pub_key.is_null() || code.is_null() {
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
    let pub_key = match CStr::from_ptr(pub_key).to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let code = match CStr::from_ptr(code).to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };

    // Everything a caller could have got wrong is refused here, before
    // the socket opens: a bad call must not cost the device an attempt,
    // or its port.
    let (host, port) = match uri::parse(uri) {
        Ok(Uri::Tcp { host, port }) => (host, port),
        Ok(Uri::Usb(_)) => return error::fail_invalid_uri("pairing is tcp:// only"),
        Err(e) => return error::fail_ffi_connect(FfiConnectError::Uri(e)),
    };
    if code.is_empty() {
        return error::fail_invalid_arg("pairing code is empty");
    }

    // The line the device stores is derived from the private key, so
    // the caller's name goes into it and the caller's blob is checked
    // against it. The trailing newline is what a file read gives.
    let pub_key = pub_key.trim_end();
    let (blob, name) = pub_key.split_once(' ').unwrap_or((pub_key, ""));
    let key = match AdbKey::from_pkcs8_pem(priv_pem, &mut OsRng, name) {
        Ok(k) => k,
        Err(e @ (KeyError::InvalidName | KeyError::NameTooLong(_))) => {
            return error::fail_invalid_arg(e)
        }
        Err(e) => return error::fail_auth(format!("parse private key: {e}")),
    };
    let line = key.public_key_line();
    let derived = line
        .iter()
        .position(|&b| b == b' ')
        .map_or(line, |at| &line[..at]);
    if derived != blob.as_bytes() {
        return error::fail_invalid_arg("public key does not belong to the private key");
    }

    let tls = match crate::auth::tls_config_for(&key) {
        Ok(c) => c,
        Err(e) => return error::fail_internal(e),
    };

    let socket = match transport::connect_tcp(host, port) {
        Ok(s) => s,
        Err(e) => return error::fail_ffi_connect(FfiConnectError::Tcp(e)),
    };
    let mut transport = MaybeTls::plain(socket);
    let paired = match crate::block_on::block_on(pair(&mut transport, &tls, &key, code, &mut OsRng))
    {
        Ok(p) => p,
        Err(e) => return error::fail_pairing(e),
    };

    // The device has the key and is closing its port; a close_notify
    // is a courtesy, and nothing here depends on it going out.
    let _ = crate::block_on::block_on(transport.shutdown());
    crate::copy_out(paired.guid.as_bytes(), guid, guid_cap, out_guid_len);
    AdbStatus::Ok
}
