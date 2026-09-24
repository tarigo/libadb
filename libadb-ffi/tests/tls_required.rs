//! A device that wants TLS from a call that cannot start it is named as
//! such, with advice a C caller can act on.

use std::ffi::{c_void, CStr, CString};
use std::ptr;

#[path = "common/common.rs"]
mod common;
use common::fake_adbd_demanding_tls;

unsafe extern "C" fn never_signs(
    _user_data: *mut c_void,
    _token: *const u8,
    _token_len: usize,
    _out_signature: *mut u8,
    _out_capacity: usize,
    _out_length: *mut usize,
) -> adb::AdbStatus {
    adb::AdbStatus::Auth
}

fn last_error() -> String {
    let p = adb::adb_last_error();
    assert!(!p.is_null(), "no error message was set");
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[test]
fn a_callback_authenticator_meets_stls_with_tls_required() {
    let (addr, device) = fake_adbd_demanding_tls();
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2,delayed_ack").unwrap();
    let pubkey = b"unused\0";
    let auth = adb::adb_authenticator_t {
        public_key: pubkey.as_ptr(),
        public_key_len: pubkey.len(),
        sign: Some(never_signs),
        user_data: ptr::null_mut(),
    };

    let mut conn = ptr::null_mut();
    let status = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(status, adb::AdbStatus::TlsRequired, "{}", last_error());
    assert!(conn.is_null());

    // The advice fits the build: without the feature, build with it;
    // with it, the callback is what stands in the way.
    let message = last_error();
    #[cfg(not(feature = "tls"))]
    assert!(message.contains("`tls` feature"), "{message}");
    #[cfg(feature = "tls")]
    assert!(message.contains("adb_connect"), "{message}");

    device.join().unwrap();
}

#[cfg(not(feature = "tls"))]
#[test]
fn adb_connect_without_the_feature_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let dir_c = CString::new(dir.path().to_str().unwrap()).unwrap();
    let mut key = ptr::null_mut();
    let status = unsafe { adb::adb_key_load_or_generate(dir_c.as_ptr(), ptr::null(), &mut key) };
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());

    let (addr, device) = fake_adbd_demanding_tls();
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2,delayed_ack").unwrap();
    let mut conn = ptr::null_mut();
    let status = unsafe {
        adb::adb_connect(
            uri.as_ptr(),
            adb::adb_key_private_key_pem(key),
            adb::adb_key_public_key(key),
            banner.as_ptr(),
            &mut conn,
        )
    };
    assert_eq!(status, adb::AdbStatus::TlsRequired, "{}", last_error());
    assert!(conn.is_null());
    let message = last_error();
    assert!(message.contains("`tls` feature"), "{message}");
    assert!(message.contains("adb tcpip"), "{message}");

    unsafe { adb::adb_key_free(key) };
    device.join().unwrap();
}
