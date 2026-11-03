//! A build without a USB backend still takes `usb://`, and says when
//! connecting that there is no backend to serve it.

#![cfg(not(any(feature = "nusb", feature = "rusb")))]

use std::ffi::{c_void, CStr, CString};
use std::ptr;

/// Nothing is dialled, so this is only here to satisfy the signature.
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

#[test]
fn usb_is_a_connect_error_that_names_the_missing_backend() {
    let uri = CString::new("usb://").unwrap();
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
    assert_eq!(status, adb::AdbStatus::Connect);
    assert!(conn.is_null());

    let p = adb::adb_last_error();
    assert!(!p.is_null(), "no error message was set");
    let message = unsafe { CStr::from_ptr(p) }.to_string_lossy();
    assert!(message.contains("USB backend compiled in"), "{message}");
}
