//! Two bindgen passes over the hand-written C header.
//!
//! The signatures pass splices the crate's own opaque and repr types
//! into the generated declarations, so the test can compare function
//! pointers with the real `extern "C"` items — any argument or return
//! type the header gets wrong fails to compile. The values pass takes
//! the header at its word, so enum values and struct layouts can be
//! asserted against the Rust side at run time.

use std::path::PathBuf;

fn main() {
    let header = "../libadb-ffi/include/libadb.h";
    println!("cargo:rerun-if-changed={header}");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header(header)
        .use_core()
        .ctypes_prefix("core::ffi")
        .allowlist_function("adb_.*")
        .blocklist_type("adb_connection")
        .blocklist_type("adb_connection_t")
        .blocklist_type("adb_shell")
        .blocklist_type("adb_shell_t")
        .blocklist_type("adb_status_t")
        .blocklist_type("adb_authenticator_t")
        .blocklist_type("adb_sign_fn")
        .raw_line("use adb::{adb_authenticator_t, adb_connection_t, adb_shell_t};")
        .raw_line("pub type adb_status_t = adb::AdbStatus;")
        .layout_tests(false)
        .generate()
        .expect("bindgen (signatures pass)")
        .write_to_file(out.join("signatures.rs"))
        .expect("write signatures.rs");

    bindgen::Builder::default()
        .header(header)
        .use_core()
        .ctypes_prefix("core::ffi")
        .allowlist_type("adb_status_t")
        .allowlist_type("adb_authenticator_t")
        .allowlist_type("adb_feature_t")
        .allowlist_var("ADB_.*")
        .generate()
        .expect("bindgen (values pass)")
        .write_to_file(out.join("values.rs"))
        .expect("write values.rs");
}
