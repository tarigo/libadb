//! `adb_read_channel` promises that `ADB_OK` never comes back with zero
//! bytes read. This checks it keeps that promise.

use std::ffi::{c_void, CString};
use std::ptr;

#[path = "common/common.rs"]
mod common;
use common::fake_adbd_pushing;

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

/// Connect to a device that pushes `hello` into the channel, and return
/// the connection and the channel id.
fn connected_with_data() -> (*mut adb::adb_connection_t, u64) {
    connected_pushing(vec![b"hello".to_vec()])
}

/// Connect to a device that pushes `pushes` into the channel — one
/// WRTE per entry — and return the connection and the channel id.
fn connected_pushing(pushes: Vec<Vec<u8>>) -> (*mut adb::adb_connection_t, u64) {
    let (addr, _rx, _parked) = fake_adbd_pushing(pushes);
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
    assert_eq!(status, adb::AdbStatus::Ok, "connect failed");

    let dest = b"shell,v2,raw:\0";
    let mut id = 0u64;
    let status = unsafe { adb::adb_open_channel(conn, dest.as_ptr(), dest.len(), &mut id) };
    assert_eq!(status, adb::AdbStatus::Ok, "open failed");
    (conn, id)
}

#[test]
fn a_read_into_no_space_is_rejected_rather_than_returning_zero() {
    let (conn, id) = connected_with_data();

    let mut read = usize::MAX;
    let status = unsafe { adb::adb_read_channel(conn, id, ptr::null_mut(), 0, &mut read) };
    assert_eq!(
        status,
        adb::AdbStatus::InvalidArg,
        "a zero-length read must not report success"
    );

    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn a_read_with_space_returns_what_the_device_sent() {
    let (conn, id) = connected_with_data();

    let mut buf = [0u8; 32];
    let mut read = 0usize;
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    assert_eq!(status, adb::AdbStatus::Ok, "read failed");
    assert_eq!(&buf[..read], b"hello");

    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn an_empty_write_is_read_past_rather_than_reported_as_zero() {
    let (conn, id) = connected_pushing(vec![Vec::new(), b"hello".to_vec()]);

    let mut buf = [0u8; 32];
    let mut read = 0usize;
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    assert_eq!(status, adb::AdbStatus::Ok, "read failed");
    assert_eq!(
        &buf[..read],
        b"hello",
        "the zero-length WRTE must not surface as a zero-byte success"
    );

    unsafe { adb::adb_connection_free(conn) };
}
