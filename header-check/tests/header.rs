//! The hand-written `libadb.h` against the Rust implementation.
//!
//! Function signatures are checked at compile time: the `sig` module
//! declares every `adb_*` function with the types the *header*
//! promises (bindgen, with the crate's own handle types spliced in),
//! and `same()` unifies each declaration with the real item as one
//! function-pointer type — a header that disagrees about any argument,
//! arity or return type does not compile. This is exactly the class of
//! bug where `adb_channel_id_t` was once four bytes narrower than the
//! implementation.
//!
//! Enum values and struct layout are data, not types, so the `val`
//! module takes the header at its word and the tests assert them
//! against the Rust side at run time.

#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![allow(clippy::missing_safety_doc)]

use core::ffi::CStr;

mod sig {
    #![allow(dead_code, unsafe_op_in_unsafe_fn)]
    // The opaque handle types are spliced in from the crate and are
    // not repr(C) — irrelevant here, since they only ever appear
    // behind pointers and these declarations exist to be compared,
    // not called.
    #![allow(improper_ctypes)]
    include!(concat!(env!("OUT_DIR"), "/signatures.rs"));
}

mod val {
    #![allow(dead_code, unsafe_op_in_unsafe_fn)]
    include!(concat!(env!("OUT_DIR"), "/values.rs"));
}

fn same<T>(_: T, _: T) {}

macro_rules! fn_ptr_normalizers {
    ($($name:ident($($arg:ident),*);)*) => {
        $(fn $name<$($arg,)* R>(
            f: unsafe extern "C" fn($($arg),*) -> R,
        ) -> unsafe extern "C" fn($($arg),*) -> R {
            f
        })*
    };
}

fn_ptr_normalizers! {
    p0();
    p1(A);
    p2(A, B);
    p3(A, B, C);
    p4(A, B, C, D);
    p5(A, B, C, D, E);
    p6(A, B, C, D, E, F);
    p8(A, B, C, D, E, F, G, H);
}

/// Every function the header declares, unified with the real item.
/// Compilation is the assertion; the test exists so a green run
/// records that the comparison happened.
#[test]
fn function_signatures_match_the_header() {
    same(p0(sig::adb_last_error), p0(adb::adb_last_error));

    same(p5(sig::adb_connect), p5(adb::adb_connect));
    same(
        p4(sig::adb_connect_with_authenticator),
        p4(adb::adb_connect_with_authenticator),
    );
    same(
        p3(sig::adb_connection_set_io_timeout_ms),
        p3(adb::adb_connection_set_io_timeout_ms),
    );
    same(p1(sig::adb_connection_free), p1(adb::adb_connection_free));
    same(
        p1(sig::adb_connection_max_payload),
        p1(adb::adb_connection_max_payload),
    );
    same(
        p1(sig::adb_connection_delayed_ack),
        p1(adb::adb_connection_delayed_ack),
    );
    same(
        p4(sig::adb_connection_device_banner),
        p4(adb::adb_connection_device_banner),
    );
    same(
        p2(sig::adb_connection_has_feature),
        p2(adb::adb_connection_has_feature),
    );
    same(p1(sig::adb_feature_name), p1(adb::adb_feature_name));
    same(
        p4(sig::adb_connection_features),
        p4(adb::adb_connection_features),
    );

    same(p4(sig::adb_open_channel), p4(adb::adb_open_channel));
    same(p5(sig::adb_read_channel), p5(adb::adb_read_channel));
    same(p4(sig::adb_write_channel), p4(adb::adb_write_channel));
    same(p2(sig::adb_close_channel), p2(adb::adb_close_channel));

    same(p6(sig::adb_reverse_forward), p6(adb::adb_reverse_forward));
    same(p2(sig::adb_reverse_remove), p2(adb::adb_reverse_remove));
    same(
        p1(sig::adb_reverse_remove_all),
        p1(adb::adb_reverse_remove_all),
    );
    same(p4(sig::adb_reverse_list), p4(adb::adb_reverse_list));
    same(p4(sig::adb_accept_channel), p4(adb::adb_accept_channel));
    same(p2(sig::adb_incoming_accept), p2(adb::adb_incoming_accept));
    same(p1(sig::adb_incoming_reject), p1(adb::adb_incoming_reject));

    same(p8(sig::adb_shell_open), p8(adb::adb_shell_open));
    same(p1(sig::adb_shell_free), p1(adb::adb_shell_free));
    same(p5(sig::adb_shell_read_frame), p5(adb::adb_shell_read_frame));
    same(
        p3(sig::adb_shell_write_stdin),
        p3(adb::adb_shell_write_stdin),
    );
    same(
        p1(sig::adb_shell_close_stdin),
        p1(adb::adb_shell_close_stdin),
    );
    same(
        p3(sig::adb_shell_set_window_size),
        p3(adb::adb_shell_set_window_size),
    );
    same(p1(sig::adb_shell_close), p1(adb::adb_shell_close));
}

#[test]
fn status_values_match_the_header() {
    use adb::AdbStatus;

    let pairs: &[(val::adb_status_t, AdbStatus)] = &[
        (val::adb_status_t_ADB_OK, AdbStatus::Ok),
        (val::adb_status_t_ADB_ERR_INVALID_ARG, AdbStatus::InvalidArg),
        (val::adb_status_t_ADB_ERR_INVALID_URI, AdbStatus::InvalidUri),
        (val::adb_status_t_ADB_ERR_CONNECT, AdbStatus::Connect),
        (val::adb_status_t_ADB_ERR_IO, AdbStatus::Io),
        (val::adb_status_t_ADB_ERR_AUTH, AdbStatus::Auth),
        (val::adb_status_t_ADB_ERR_PROTOCOL, AdbStatus::Protocol),
        (
            val::adb_status_t_ADB_ERR_CHANNEL_CLOSED,
            AdbStatus::ChannelClosed,
        ),
        (
            val::adb_status_t_ADB_ERR_NO_FREE_CHANNELS,
            AdbStatus::NoFreeChannels,
        ),
        (
            val::adb_status_t_ADB_ERR_DESYNCHRONIZED,
            AdbStatus::Desynchronized,
        ),
        (val::adb_status_t_ADB_ERR_REVERSE, AdbStatus::Reverse),
        (val::adb_status_t_ADB_ERR_INTERNAL, AdbStatus::Internal),
    ];
    for &(header, rust) in pairs {
        assert_eq!(
            header as i64, rust as i64,
            "{rust:?} disagrees between the header and the enum"
        );
    }
}

#[test]
fn authenticator_layout_matches_the_header() {
    use core::mem::{align_of, offset_of, size_of};

    assert_eq!(
        size_of::<val::adb_authenticator_t>(),
        size_of::<adb::adb_authenticator_t>()
    );
    assert_eq!(
        align_of::<val::adb_authenticator_t>(),
        align_of::<adb::adb_authenticator_t>()
    );
    assert_eq!(
        offset_of!(val::adb_authenticator_t, public_key),
        offset_of!(adb::adb_authenticator_t, public_key)
    );
    assert_eq!(
        offset_of!(val::adb_authenticator_t, public_key_len),
        offset_of!(adb::adb_authenticator_t, public_key_len)
    );
    assert_eq!(
        offset_of!(val::adb_authenticator_t, sign),
        offset_of!(adb::adb_authenticator_t, sign)
    );
    assert_eq!(
        offset_of!(val::adb_authenticator_t, user_data),
        offset_of!(adb::adb_authenticator_t, user_data)
    );
}

#[test]
fn feature_constants_match_the_implementation() {
    // The header promises a dense list ending at TRACK_APP; the
    // implementation must answer a name for exactly that range.
    for value in 0..=val::ADB_FEATURE_TRACK_APP {
        assert!(
            !adb::adb_feature_name(value).is_null(),
            "feature {value} is in the header but unknown to the library"
        );
    }
    assert!(
        adb::adb_feature_name(val::ADB_FEATURE_TRACK_APP + 1).is_null(),
        "the library knows features the header does not list"
    );

    // Spot checks: the wire name is the constant's suffix, lowercased.
    for (value, wire) in [
        (val::ADB_FEATURE_ABB, "abb"),
        (val::ADB_FEATURE_DELAYED_ACK, "delayed_ack"),
        (val::ADB_FEATURE_SHELL_V2, "shell_v2"),
        (val::ADB_FEATURE_TRACK_APP, "track_app"),
    ] {
        let name = unsafe { CStr::from_ptr(adb::adb_feature_name(value)) };
        assert_eq!(name.to_str().unwrap(), wire);
    }
}
