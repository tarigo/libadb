//! A channel id packs a table slot beside the wire id. An id whose slot
//! lies outside the connection's table is one no call returns, and the
//! channel calls refuse it as an argument instead of treating it as a
//! closed channel.

use std::ffi::{c_void, CStr, CString};
use std::ptr;

use libadb::ConnectionConfig;

#[path = "common/common.rs"]
mod common;
use common::fake_adbd_pushing;

/// The low half of an id: the slot. `adb_connect_with_authenticator`
/// opens its connection with the default config, hence this many.
const SLOT_MASK: u64 = 0xFFFF_FFFF;
const SLOTS: u64 = ConnectionConfig::DEFAULT_MAX_CHANNELS as u64;

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

/// Connect to a device that pushes `hello` into the one channel it
/// accepts, and return the connection and that channel's id.
fn connected() -> (*mut adb::adb_connection_t, u64) {
    let (addr, _rx, _parked) = fake_adbd_pushing(vec![b"hello".to_vec()]);
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

fn last_error() -> String {
    let p = adb::adb_last_error();
    assert!(!p.is_null(), "a failed call leaves its reason");
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn read(conn: *mut adb::adb_connection_t, id: u64) -> (adb::AdbStatus, Vec<u8>) {
    let mut buf = [0u8; 32];
    let mut read = 0usize;
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    (status, buf[..read].to_vec())
}

#[test]
fn an_id_past_the_channel_table_is_an_invalid_argument() {
    let (conn, id) = connected();
    let wire = id & !SLOT_MASK;

    // The first slot past the table, and the furthest a slot can reach.
    for bogus in [wire | SLOTS, wire | SLOT_MASK] {
        let (status, _) = read(conn, bogus);
        assert_eq!(status, adb::AdbStatus::InvalidArg, "read {bogus:#x}");
        assert!(last_error().contains("slot"), "read: {}", last_error());

        let ping = b"ping";
        let status = unsafe { adb::adb_write_channel(conn, bogus, ping.as_ptr(), ping.len()) };
        assert_eq!(status, adb::AdbStatus::InvalidArg, "write {bogus:#x}");

        let status = unsafe { adb::adb_close_channel(conn, bogus) };
        assert_eq!(status, adb::AdbStatus::InvalidArg, "close {bogus:#x}");
    }

    let (status, data) = read(conn, id);
    assert_eq!(status, adb::AdbStatus::Ok, "the real channel is untouched");
    assert_eq!(data, b"hello");

    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn an_empty_slot_inside_the_table_is_a_closed_channel() {
    let (conn, id) = connected();
    let last = (id & !SLOT_MASK) | (SLOTS - 1);
    assert_ne!(last, id, "the one open channel sits in the first slot");

    let (status, _) = read(conn, last);
    assert_eq!(
        status,
        adb::AdbStatus::ChannelClosed,
        "a slot the table has is a channel that is not open, not a bad id"
    );

    unsafe { adb::adb_connection_free(conn) };
}
