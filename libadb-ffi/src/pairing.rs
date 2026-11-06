use alloc::format;
use core::ffi::{c_char, CStr};

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{AdbKey, KeyName};
use libadb::pairing::pair;
use libadb::transport::runtime::{Inline, Runtime};
use libadb::transport::tls::MaybeTls;
use libadb::uri::{self, Uri};

use crate::error::{self, AdbStatus};
use crate::transport::FfiConnectError;

/// Pair with a device: put the key in `priv_key_pem` into its trusted
/// store through "Pair device with pairing code" on its Wireless
/// debugging screen (SPAKE2 inside TLS, as `adb pair` does).
///
/// `uri` is the `tcp://` pairing port shown beside the code, `pub_key`
/// the matching ADB-format public key line, and `code` what the dialog
/// shows. `guid`, `guid_cap` and `out_guid_len` receive the device's
/// GUID, with the truncate-and-report convention of
/// [`adb_connection_features`](crate::adb_connection_features).
///
/// Returns [`AdbStatus::Ok`] once the device has stored the key. Blocks
/// until the exchange ends; there is no timeout. See `libadb.h`.
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
    // SAFETY: all four are non-null, and C strings per `# Safety`.
    let (uri, priv_key_pem, pub_key, code) = unsafe {
        (
            CStr::from_ptr(uri),
            CStr::from_ptr(priv_key_pem),
            CStr::from_ptr(pub_key),
            CStr::from_ptr(code),
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
    let pub_key = match pub_key.to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let code = match code.to_str() {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };

    let (host, port) = match uri::parse(uri) {
        Ok(Uri::Tcp { host, port }) => (host, port),
        Ok(Uri::Usb(_)) => return error::fail_invalid_uri("pairing is tcp:// only"),
        Err(e) => return error::fail_ffi_connect(FfiConnectError::Uri(e)),
    };
    if code.is_empty() {
        return error::fail_invalid_arg("pairing code is empty");
    }

    let pub_key = pub_key.trim_end_matches(['\r', '\n']);
    let (blob, name) = pub_key.split_once(' ').unwrap_or((pub_key, ""));
    let name = match KeyName::new(name) {
        Ok(n) => n,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let key = match AdbKey::from_pkcs8_pem(priv_pem, &mut OsRng, name) {
        Ok(k) => k,
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

    let socket = match crate::block_on::block_on(Inline::connect_tcp(host, port)) {
        Ok(s) => s,
        Err(e) => return error::fail_ffi_connect(FfiConnectError::Tcp(e)),
    };
    let mut transport = MaybeTls::plain(socket);
    let paired = match crate::block_on::block_on(pair(&mut transport, &tls, &key, code, &mut OsRng))
    {
        Ok(p) => p,
        Err(e) => return error::fail_pairing(e),
    };

    let _ = crate::block_on::block_on(transport.shutdown());
    // SAFETY: `guid` and `out_guid_len` are NULL or writable as sized, per `# Safety`.
    unsafe { crate::slice::copy_out(paired.guid.as_bytes(), guid, guid_cap, out_guid_len) };
    AdbStatus::Ok
}
