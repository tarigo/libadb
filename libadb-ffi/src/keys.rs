use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use std::path::Path;

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::zeroize::Zeroizing;
use libadb::keys::{store, KeyName};

use crate::error::{self, AdbStatus};

const DEFAULT_NAME: &str = "libadb@host";

/// An RSA host key loaded from, or generated into, a key directory.
///
/// Free it with [`adb_key_free`].
#[allow(non_camel_case_types)]
pub struct adb_key_t {
    private_key_pem: Zeroizing<Vec<u8>>,
    public_key: CString,
}

/// Load `<android_dir>/adbkey`, generating and persisting a key when
/// there is none. `name` is the `user@host` comment shown in the
/// device's authorization dialog; NULL picks a default. On success
/// `*out` receives a handle to release with [`adb_key_free`]. See
/// `libadb.h`.
///
/// # Safety
/// `android_dir` and, if non-NULL, `name` must be valid null-terminated
/// C strings. `out` must point to a writable `adb_key_t*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_key_load_or_generate(
    android_dir: *const c_char,
    name: *const c_char,
    out: *mut *mut adb_key_t,
) -> AdbStatus {
    error::clear_last_error();
    if android_dir.is_null() || out.is_null() {
        return error::fail_invalid_arg("null pointer");
    }

    // SAFETY: non-null, and a C string per `# Safety`.
    let dir = unsafe { CStr::from_ptr(android_dir) };
    #[cfg(unix)]
    let dir = {
        use std::os::unix::ffi::OsStrExt;
        Path::new(std::ffi::OsStr::from_bytes(dir.to_bytes()))
    };
    #[cfg(not(unix))]
    let dir = match dir.to_str() {
        Ok(s) => Path::new(s),
        Err(e) => return error::fail_invalid_arg(e),
    };
    let name = if name.is_null() {
        DEFAULT_NAME
    } else {
        // SAFETY: non-null, and a C string per `# Safety`.
        match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) => s,
            Err(e) => return error::fail_invalid_arg(e),
        }
    };

    let name = match KeyName::new(name) {
        Ok(n) => n,
        Err(e) => return error::fail_invalid_arg(e),
    };

    let key = match store::load_or_generate(dir, &mut OsRng, name) {
        Ok(k) => k,
        Err(e @ (store::StoreError::Malformed { .. } | store::StoreError::NotAKeyFile { .. })) => {
            return error::fail_auth(e)
        }
        Err(e @ store::StoreError::Key(_)) => return error::fail_internal(e),
        Err(e @ store::StoreError::Io { .. }) => return error::fail_io(e),
    };

    let pem = match key.to_pkcs8_pem() {
        Ok(p) => p,
        Err(e) => return error::fail_internal(e),
    };
    let Ok(public_key) = CString::new(key.public_key_line()) else {
        return error::fail_internal("key material contains a NUL");
    };
    if pem.as_bytes().contains(&0) {
        return error::fail_internal("key material contains a NUL");
    }
    let mut private_key_pem = Zeroizing::new(Vec::with_capacity(pem.len() + 1));
    private_key_pem.extend_from_slice(pem.as_bytes());
    private_key_pem.push(0);

    let handle = Box::into_raw(Box::new(adb_key_t {
        private_key_pem,
        public_key,
    }));
    // SAFETY: non-null, and writable per `# Safety`.
    unsafe { *out = handle };
    AdbStatus::Ok
}

/// The PKCS#8 PEM private key, ready to pass to `adb_connect`; NULL if
/// `key` is NULL. The string is owned by `key` and stays valid until
/// [`adb_key_free`].
///
/// # Safety
/// `key` must be NULL or a handle from [`adb_key_load_or_generate`]
/// that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_key_private_key_pem(key: *const adb_key_t) -> *const c_char {
    // SAFETY: NULL or a live handle, per `# Safety`.
    match unsafe { key.as_ref() } {
        Some(k) => k.private_key_pem.as_ptr() as *const c_char,
        None => core::ptr::null(),
    }
}

/// The ADB-format public key — the `adbkey.pub` line — ready to pass to
/// `adb_connect`; NULL if `key` is NULL. The string is owned by `key`
/// and stays valid until [`adb_key_free`].
///
/// # Safety
/// `key` must be NULL or a handle from [`adb_key_load_or_generate`]
/// that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_key_public_key(key: *const adb_key_t) -> *const c_char {
    // SAFETY: NULL or a live handle, per `# Safety`.
    match unsafe { key.as_ref() } {
        Some(k) => k.public_key.as_ptr(),
        None => core::ptr::null(),
    }
}

/// Release a handle from [`adb_key_load_or_generate`]. NULL is a no-op.
///
/// # Safety
/// `key` must be NULL or a handle from [`adb_key_load_or_generate`],
/// not yet freed, and not used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_key_free(key: *mut adb_key_t) {
    if !key.is_null() {
        // SAFETY: a live handle from `adb_key_load_or_generate`, which boxed it, per `# Safety`.
        drop(unsafe { Box::from_raw(key) });
    }
}
