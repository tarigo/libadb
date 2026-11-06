//! C ABI for [`libadb`].
//!
//! The API is synchronous from the caller's perspective: each async
//! operation is driven to completion by a tiny internal executor. No
//! tokio or smol runtime is required.
//!
//! `include/libadb.h` is the contract: it says in full what each call
//! does and returns, how it fails, what stays valid and what the caller
//! must do. The rustdoc here gives a summary and the `# Safety` section.
//!
//! Under the hood a handle is a split [`Reader`] / [`Writer`] pair
//! sharing a reference-counted state. A write never waits for the
//! [`Reader`]'s mutex, so a thread blocked in a long read does not
//! prevent another thread from writing — which is what makes
//! interactive shell sessions usable from C without any async runtime.
//!
//! [`Reader::run`] is never started, so only a call holding the read
//! lock takes packets off the connection, and that includes the OKAY
//! [`Writer::write_channel`] waits for. A write waiting for the device
//! with no read call running reads the connection itself, under that
//! lock. A read does not wait for the lock: finding it taken, the read
//! takes what the holder dispatches for its channel, and the lock once
//! it comes free.
//!
//! # Feature flags
//!
//! TCP support is always compiled in and needs no async runtime. USB
//! support is opt-in: enable `usb` (alias for the pure-Rust `nusb`
//! backend) or `rusb` (libusb). Both may be on at once, and `usb://`
//! then goes to `nusb`, since [`adb_connect`] cannot choose a backend.
//!
//! `tls` answers a wireless-debugging device's `STLS` (Android 11+)
//! from [`adb_connect`] with TLS 1.3, presenting the caller's key in a
//! certificate; without it such a device is [`AdbStatus::TlsRequired`].
//! [`adb_connect_with_authenticator`] stays in the clear either way.
//!
//! `pairing` (implies `tls`) adds `adb_pair`, the `adb pair` exchange
//! against the device's pairing dialog: the one way to put a key on a
//! device that has never seen it without a USB cable.
//!
//! [`Reader`]: libadb::Reader
//! [`Reader::run`]: libadb::Reader::run
//! [`Writer`]: libadb::Writer
//! [`Writer::write_channel`]: libadb::Writer::write_channel

#![no_std]
#![allow(unsafe_code)]
#![warn(unsafe_op_in_unsafe_fn)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
extern crate std;

#[macro_use]
mod macros;

mod auth;
mod block_on;
mod channel;
mod connection;
mod error;
mod feature;
mod incoming;
mod keys;
#[cfg(feature = "pairing")]
mod pairing;
mod reverse;
mod shell;
mod slice;
mod transport;

pub use auth::{adb_authenticator_t, AdbSignFn};
// Also reachable through the C ABI; re-exported so Rust consumers of the
// rlib — the crate's own integration tests among them — can name them.
pub use channel::{adb_close_channel, adb_open_channel, adb_read_channel, adb_write_channel};
pub use connection::{
    adb_connect, adb_connect_with_authenticator, adb_connection_delayed_ack,
    adb_connection_device_banner, adb_connection_free, adb_connection_max_payload,
    adb_connection_set_io_timeout_ms, adb_connection_t,
};
pub use error::{adb_last_error, AdbStatus};
pub use feature::{adb_connection_features, adb_connection_has_feature, adb_feature_name};
pub use incoming::{adb_accept_channel, adb_incoming_accept, adb_incoming_reject};
pub use keys::{
    adb_key_free, adb_key_load_or_generate, adb_key_private_key_pem, adb_key_public_key, adb_key_t,
};
#[cfg(feature = "pairing")]
pub use pairing::adb_pair;
pub use reverse::{
    adb_reverse_forward, adb_reverse_list, adb_reverse_remove, adb_reverse_remove_all,
};
pub use shell::{
    adb_shell_close, adb_shell_close_stdin, adb_shell_free, adb_shell_open, adb_shell_read_frame,
    adb_shell_set_window_size, adb_shell_t, adb_shell_write_stdin,
};
