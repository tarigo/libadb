//! The C ABI's view of the host key store.
//!
//! The key directory is an argument, never something the library
//! resolves: a C caller that wants `~/.android` says so. What the two
//! accessors hand back is exactly what `adb_connect` expects.

use std::ffi::{CStr, CString};
use std::fs;
use std::ptr;

use adb::{adb_key_free, adb_key_load_or_generate, adb_key_private_key_pem, adb_key_public_key};
use adb::{adb_last_error, AdbStatus};

const NAME: &str = "unit@test";

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Load or generate in `dir`, asserting success.
fn load(dir: &std::path::Path) -> *mut adb::adb_key_t {
    let mut key = ptr::null_mut();
    let status = unsafe {
        adb_key_load_or_generate(
            c(dir.to_str().unwrap()).as_ptr(),
            c(NAME).as_ptr(),
            &mut key,
        )
    };
    assert_eq!(status, AdbStatus::Ok, "load_or_generate failed");
    assert!(!key.is_null());
    key
}

fn as_str(p: *const std::ffi::c_char) -> &'static str {
    assert!(!p.is_null());
    unsafe { CStr::from_ptr(p) }.to_str().unwrap()
}

#[test]
fn a_key_is_generated_on_first_use_and_reloaded_verbatim_after() {
    let dir = tempfile::tempdir().unwrap();

    let first = load(dir.path());
    let generated_pub = as_str(unsafe { adb_key_public_key(first) }).to_string();
    let pem = as_str(unsafe { adb_key_private_key_pem(first) }).to_string();
    let on_disk = fs::read(dir.path().join("adbkey")).unwrap();
    unsafe { adb_key_free(first) };

    let second = load(dir.path());
    let reloaded_pub = as_str(unsafe { adb_key_public_key(second) });

    assert!(
        pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "adb_connect takes PKCS#8 PEM: {pem:.40}"
    );
    assert!(
        generated_pub.ends_with(" unit@test"),
        "the public blob carries the name and no trailing NUL byte: {generated_pub:.40}"
    );
    assert_eq!(
        reloaded_pub, generated_pub,
        "a second run must reuse the key the device was asked to trust"
    );
    assert_eq!(
        fs::read(dir.path().join("adbkey")).unwrap(),
        on_disk,
        "and leave the file alone"
    );
    unsafe { adb_key_free(second) };
}

#[test]
fn a_corrupt_adbkey_maps_to_auth_and_sets_last_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("adbkey"), b"this is not a key").unwrap();

    let mut key = ptr::null_mut();
    let status = unsafe {
        adb_key_load_or_generate(
            c(dir.path().to_str().unwrap()).as_ptr(),
            ptr::null(),
            &mut key,
        )
    };

    assert_eq!(status, AdbStatus::Auth);
    assert!(key.is_null(), "nothing to free on failure");
    let msg = as_str(adb_last_error());
    assert!(msg.contains("adbkey"), "the message names the file: {msg}");
    assert_eq!(
        fs::read(dir.path().join("adbkey")).unwrap(),
        b"this is not a key",
        "an identity the device may trust is never overwritten"
    );
}

#[cfg(unix)]
#[test]
fn a_directory_whose_name_is_not_utf8_is_still_a_directory() {
    // A C caller passes bytes, and a Unix path is bytes: `$HOME` need
    // not be valid UTF-8 for `fopen` to have worked all along.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join(OsStr::from_bytes(b"\xffnot-utf8"));
    fs::create_dir(&dir).unwrap();

    let mut key = ptr::null_mut();
    let as_c = CString::new(dir.as_os_str().as_bytes()).unwrap();
    let status = unsafe { adb_key_load_or_generate(as_c.as_ptr(), c(NAME).as_ptr(), &mut key) };

    assert_eq!(status, AdbStatus::Ok);
    assert!(!key.is_null());
    assert!(
        dir.join("adbkey").exists(),
        "the key landed in that directory"
    );
    unsafe { adb_key_free(key) };
}

#[test]
fn a_binary_adbkey_maps_to_auth_like_any_unusable_key() {
    // Not text at all — a DER file where the PEM belongs, say. The
    // header promises ADB_ERR_AUTH for key material we cannot use,
    // whichever way it is unusable.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("adbkey"), [0x30u8, 0x82, 0xFF, 0xFE]).unwrap();

    let mut key = ptr::null_mut();
    let status = unsafe {
        adb_key_load_or_generate(
            c(dir.path().to_str().unwrap()).as_ptr(),
            c(NAME).as_ptr(),
            &mut key,
        )
    };

    assert_eq!(status, AdbStatus::Auth);
    assert!(key.is_null());
    assert_eq!(
        fs::read(dir.path().join("adbkey")).unwrap(),
        [0x30, 0x82, 0xFF, 0xFE],
        "and the file is left where it was"
    );
}

#[test]
fn a_name_the_format_rejects_is_an_invalid_argument() {
    // The caller passed this in, so it is not the disk's fault and not
    // an IO failure.
    let dir = tempfile::tempdir().unwrap();
    let mut key = ptr::null_mut();

    let status = unsafe {
        adb_key_load_or_generate(
            c(dir.path().to_str().unwrap()).as_ptr(),
            c("unit@test\n").as_ptr(),
            &mut key,
        )
    };

    assert_eq!(status, AdbStatus::InvalidArg);
    assert!(key.is_null());
    assert!(
        fs::read_dir(dir.path()).unwrap().next().is_none(),
        "a rejected name writes nothing"
    );
}

#[test]
fn a_missing_directory_argument_is_an_invalid_arg() {
    let dir = tempfile::tempdir().unwrap();
    let mut key = ptr::null_mut();

    let no_dir = unsafe { adb_key_load_or_generate(ptr::null(), c(NAME).as_ptr(), &mut key) };
    let no_out = unsafe {
        adb_key_load_or_generate(
            c(dir.path().to_str().unwrap()).as_ptr(),
            c(NAME).as_ptr(),
            ptr::null_mut(),
        )
    };

    assert_eq!(no_dir, AdbStatus::InvalidArg, "the caller chooses the path");
    assert_eq!(no_out, AdbStatus::InvalidArg);
    assert!(
        fs::read_dir(dir.path()).unwrap().next().is_none(),
        "a rejected call writes nothing"
    );
}

#[test]
fn key_accessors_and_free_are_null_safe() {
    assert!(unsafe { adb_key_private_key_pem(ptr::null()) }.is_null());
    assert!(unsafe { adb_key_public_key(ptr::null()) }.is_null());
    unsafe { adb_key_free(ptr::null_mut()) };
}
