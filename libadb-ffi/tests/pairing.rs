//! `adb_pair` against a device serving its pairing port.

#![cfg(feature = "pairing")]

use std::ffi::{CStr, CString};
use std::net::TcpListener;
use std::ptr;
use std::sync::LazyLock;

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::AdbKey;

#[path = "pairing_device/pairing_device.rs"]
mod pairing_device;
use pairing_device::{spawn_pairing_device, spawn_pairing_device_that, Conduct, DEVICE_GUID};

const CODE: &str = "592781";

/// The host key, in the two forms `adb_pair` takes.
struct HostKey {
    pem: CString,
    public: String,
}

/// One host key per test binary: generating it is the slow part.
static HOST: LazyLock<HostKey> = LazyLock::new(|| {
    let key = AdbKey::generate(&mut OsRng, "unit@test").unwrap();
    HostKey {
        pem: CString::new(key.to_pkcs8_pem().unwrap().as_str()).unwrap(),
        public: String::from_utf8(key.public_key_line().to_vec()).unwrap(),
    }
});

fn last_error() -> String {
    let p = adb::adb_last_error();
    assert!(!p.is_null(), "no error message was set");
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// `adb_pair` with the C-string plumbing done and the host's own key.
fn pair_with(
    uri: &str,
    public: &str,
    code: &str,
    guid: *mut u8,
    guid_cap: usize,
    out_len: *mut usize,
) -> adb::AdbStatus {
    let uri = CString::new(uri).unwrap();
    let public = CString::new(public).unwrap();
    let code = CString::new(code).unwrap();
    unsafe {
        adb::adb_pair(
            uri.as_ptr(),
            HOST.pem.as_ptr(),
            public.as_ptr(),
            code.as_ptr(),
            guid,
            guid_cap,
            out_len,
        )
    }
}

/// `adb_pair` into a buffer, returning the status, the bytes copied and
/// the length reported.
fn pair(uri: &str, public: &str, code: &str, cap: usize) -> (adb::AdbStatus, Vec<u8>, usize) {
    let mut buf = vec![0u8; cap];
    let mut len = usize::MAX;
    let status = pair_with(uri, public, code, buf.as_mut_ptr(), buf.len(), &mut len);
    (status, buf, len)
}

/// A port nothing listens on: bound once, so it is free, then released.
/// A call that reaches the socket answers `Connect`, so a refusal that
/// must come first is told apart by its status alone — and a call that
/// wrongly went ahead fails fast rather than waiting on a port that
/// never answers.
fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

#[test]
fn the_right_code_hands_the_device_our_key() {
    let (addr, device) = spawn_pairing_device(CODE);

    let (status, buf, len) = pair(&format!("tcp://{addr}"), &HOST.public, CODE, 64);
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());
    assert_eq!(len, DEVICE_GUID.len());
    assert_eq!(&buf[..len], DEVICE_GUID.as_bytes());

    let outcome = device.join().unwrap();
    assert!(outcome.opened, "the device could not open our block");
    assert_eq!(outcome.learned_key.as_deref(), Some(HOST.public.as_str()));
}

#[test]
fn a_wrong_code_is_pairing_and_the_device_learns_nothing() {
    let (addr, device) = spawn_pairing_device(CODE);

    let (status, _, _) = pair(&format!("tcp://{addr}"), &HOST.public, "000000", 64);
    assert_eq!(status, adb::AdbStatus::Pairing, "{}", last_error());
    let message = last_error();
    assert!(message.contains("code did not match"), "{message}");

    let outcome = device.join().unwrap();
    assert!(!outcome.opened, "a wrong code must not open anything");
    assert!(outcome.learned_key.is_none());
}

#[test]
fn a_key_from_the_store_pairs_under_its_own_name() {
    // The two C APIs agree end to end: what the key accessors hand
    // out is exactly the line the device ends up storing.
    let dir = tempfile::tempdir().unwrap();
    let dir_c = CString::new(dir.path().to_str().unwrap()).unwrap();
    let name = CString::new("store@test").unwrap();
    let mut key = ptr::null_mut();
    let status = unsafe { adb::adb_key_load_or_generate(dir_c.as_ptr(), name.as_ptr(), &mut key) };
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());

    let (addr, device) = spawn_pairing_device(CODE);
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let code = CString::new(CODE).unwrap();
    let status = unsafe {
        adb::adb_pair(
            uri.as_ptr(),
            adb::adb_key_private_key_pem(key),
            adb::adb_key_public_key(key),
            code.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());

    let expected = unsafe { CStr::from_ptr(adb::adb_key_public_key(key)) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { adb::adb_key_free(key) };
    let outcome = device.join().unwrap();
    assert_eq!(outcome.learned_key.as_deref(), Some(expected.as_str()));
}

#[test]
fn a_trailing_newline_on_the_public_key_is_tolerated() {
    // What a file read gives, and what `adb_connect` accepts silently.
    let (addr, device) = spawn_pairing_device(CODE);

    let public = format!("{}\n", HOST.public);
    let (status, _, _) = pair(&format!("tcp://{addr}"), &public, CODE, 64);
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());

    let outcome = device.join().unwrap();
    assert_eq!(outcome.learned_key.as_deref(), Some(HOST.public.as_str()));
}

#[test]
fn a_public_key_that_is_not_the_private_key_s_is_refused_before_connecting() {
    let addr = closed_port();
    let other = AdbKey::generate(&mut OsRng, "other@test").unwrap();
    let other = String::from_utf8(other.public_key_line().to_vec()).unwrap();

    // `Connect` here would mean the call reached the socket first.
    let (status, _, _) = pair(&format!("tcp://{addr}"), &other, CODE, 64);
    assert_eq!(status, adb::AdbStatus::InvalidArg, "{}", last_error());
    let message = last_error();
    assert!(message.contains("does not belong"), "{message}");
}

#[test]
fn usb_is_not_a_pairing_transport() {
    let (status, _, _) = pair("usb://", &HOST.public, CODE, 64);
    assert_eq!(status, adb::AdbStatus::InvalidUri, "{}", last_error());
    let message = last_error();
    assert!(message.contains("tcp://"), "{message}");
}

#[test]
fn an_empty_code_is_refused_before_connecting() {
    let addr = closed_port();

    // `Connect` here would mean the call reached the socket first.
    let (status, _, _) = pair(&format!("tcp://{addr}"), &HOST.public, "", 64);
    assert_eq!(status, adb::AdbStatus::InvalidArg, "{}", last_error());
}

#[test]
fn null_arguments_are_invalid() {
    let uri = CString::new("tcp://127.0.0.1:1").unwrap();
    let public = CString::new(HOST.public.as_str()).unwrap();
    let code = CString::new(CODE).unwrap();
    let strings = [
        uri.as_ptr(),
        HOST.pem.as_ptr(),
        public.as_ptr(),
        code.as_ptr(),
    ];
    for missing in 0..strings.len() {
        let mut args = strings;
        args[missing] = ptr::null();
        let status = unsafe {
            adb::adb_pair(
                args[0],
                args[1],
                args[2],
                args[3],
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(
            status,
            adb::AdbStatus::InvalidArg,
            "argument {missing} left NULL"
        );
    }
}

#[test]
fn a_short_guid_buffer_truncates_and_reports() {
    let (addr, device) = spawn_pairing_device(CODE);

    let (status, buf, len) = pair(&format!("tcp://{addr}"), &HOST.public, CODE, 4);
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());
    assert_eq!(len, DEVICE_GUID.len(), "the full length is reported");
    assert_eq!(buf, DEVICE_GUID.as_bytes()[..4]);
    device.join().unwrap();
}

#[test]
fn the_guid_may_be_skipped() {
    let (addr, device) = spawn_pairing_device(CODE);
    let mut len = usize::MAX;
    let status = pair_with(
        &format!("tcp://{addr}"),
        &HOST.public,
        CODE,
        ptr::null_mut(),
        0,
        &mut len,
    );
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());
    assert_eq!(len, DEVICE_GUID.len(), "the length is still reported");
    device.join().unwrap();

    let (addr, device) = spawn_pairing_device(CODE);
    let mut buf = [0u8; 64];
    let status = pair_with(
        &format!("tcp://{addr}"),
        &HOST.public,
        CODE,
        buf.as_mut_ptr(),
        buf.len(),
        ptr::null_mut(),
    );
    assert_eq!(status, adb::AdbStatus::Ok, "{}", last_error());
    assert_eq!(&buf[..DEVICE_GUID.len()], DEVICE_GUID.as_bytes());
    device.join().unwrap();
}

#[test]
fn a_closed_pairing_port_is_connect() {
    // What a second attempt at a port that has served one pairing
    // looks like: nothing listens there any more.
    let addr = closed_port();

    let (status, _, _) = pair(&format!("tcp://{addr}"), &HOST.public, CODE, 64);
    assert_eq!(status, adb::AdbStatus::Connect, "{}", last_error());
}

#[test]
fn a_device_that_hangs_up_mid_exchange_is_pairing() {
    // The device's verdict, not a network fault: a retry into a
    // dismissed dialog cures nothing.
    let (addr, device) = spawn_pairing_device_that(CODE, Conduct::QuitEarly);

    let (status, _, _) = pair(&format!("tcp://{addr}"), &HOST.public, CODE, 64);
    assert_eq!(status, adb::AdbStatus::Pairing, "{}", last_error());
    let message = last_error();
    assert!(message.contains("closed"), "{message}");

    let outcome = device.join().unwrap();
    assert!(!outcome.opened);
}
