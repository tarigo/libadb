//! A call that fills a caller's buffer copies what fits and reports the
//! full length through `out_len`, so a caller can probe with a short
//! buffer and retry with one large enough.

use std::ffi::{c_void, CString};
use std::ptr;

#[path = "common/common.rs"]
mod common;
use common::fake_adbd_pushing;

/// What `fake_adbd_pushing` answers CNXN with.
const DEVICE_BANNER: &[u8] = b"device::features=shell_v2,delayed_ack";
/// `ADB_SHELL_V2_STDOUT` in libadb.h.
const STDOUT: u8 = 1;

/// The fake device never asks for AUTH, so this is only here to satisfy
/// the signature.
unsafe extern "C" fn never_signs(
    _user_data: *mut c_void,
    _token: *const u8,
    _token_len: usize,
    _out_signature: *mut u8,
    _out_capacity: usize,
    _out_length: *mut usize,
) -> i32 {
    adb::AdbStatus::Auth as i32
}

/// Connect to a device that writes `pushes` into the first channel the
/// host opens.
fn connect(pushes: Vec<Vec<u8>>) -> *mut adb::adb_connection_t {
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
    conn
}

#[test]
fn a_short_buffer_takes_the_banners_head_and_learns_its_length() {
    let conn = connect(Vec::new());

    let mut len = 0usize;
    let status = unsafe { adb::adb_connection_device_banner(conn, ptr::null_mut(), 0, &mut len) };
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(
        len,
        DEVICE_BANNER.len(),
        "a NULL buffer still learns the length"
    );

    let mut short = [0xAAu8; 8];
    let mut len = 0usize;
    let status = unsafe {
        adb::adb_connection_device_banner(conn, short.as_mut_ptr(), short.len(), &mut len)
    };
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(
        len,
        DEVICE_BANNER.len(),
        "the full length, not what was copied"
    );
    assert_eq!(short, DEVICE_BANNER[..8]);

    let mut room = [0xAAu8; 64];
    let mut len = 0usize;
    let status =
        unsafe { adb::adb_connection_device_banner(conn, room.as_mut_ptr(), room.len(), &mut len) };
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(&room[..len], DEVICE_BANNER);
    assert!(
        room[len..].iter().all(|&b| b == 0xAA),
        "nothing past the banner is written"
    );

    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn a_short_buffer_takes_the_frames_head_and_learns_its_length() {
    let payload = b"hello, shell";
    let mut frame = vec![STDOUT];
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    let conn = connect(vec![frame]);

    let mut sh = ptr::null_mut();
    let status =
        unsafe { adb::adb_shell_open(conn, ptr::null(), 0, false, ptr::null(), 0, 0, &mut sh) };
    assert_eq!(status, adb::AdbStatus::Ok, "shell open failed");

    let mut id = 0u8;
    let mut short = [0xAAu8; 5];
    let mut len = 0usize;
    let status = unsafe {
        adb::adb_shell_read_frame(sh, &mut id, short.as_mut_ptr(), short.len(), &mut len)
    };
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(id, STDOUT);
    assert_eq!(len, payload.len(), "the full length, not what was copied");
    assert_eq!(short, payload[..5]);

    unsafe { adb::adb_shell_close(sh) };
    unsafe { adb::adb_shell_free(sh) };
    unsafe { adb::adb_connection_free(conn) };
}
