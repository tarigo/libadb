//! ADB over TLS: wireless debugging on Android 11+.
//!
//! A device with "Wireless debugging" on answers the handshake with
//! [`Command::StartTls`](crate::protocol::command::Command::StartTls)
//! instead of CNXN or AUTH, and speaks nothing but TLS 1.3 afterwards.
//! [`Connection::connect_tls`](crate::Connection::connect_tls) takes it
//! up on that; this module holds what the handshake needs.
//!
//! # What authenticates whom
//!
//! The device authenticates the host by the public key inside the
//! client certificate, checked against the same trusted-key store a USB
//! authorisation prompt fills. A key that was confirmed over USB is
//! therefore accepted here with no pairing at all.
//!
//! The host does not authenticate the device. Its certificate is
//! self-signed and belongs to no chain, and `adb` accepts whatever it
//! is handed; [`TlsClientConfig::adb`] does the same. What stands in
//! for it is the device's position on the network and the ADB layer
//! above. If that is not enough for you, build your own verifier and
//! pass it through [`TlsClientConfig::from_rustls`].
//!
//! # Not covered
//!
//! * `adb pair` — the SPAKE2 exchange that puts a *new* key on a device.
//!   A key the device already trusts does not need it.
//! * Finding the port. Wireless debugging picks a fresh one every time
//!   it is switched on and announces it over DNS-SD; this crate does no
//!   service discovery, so the caller supplies host and port.
//! * TLS over USB. adbd never offers STLS there.

mod config;
mod identity;

pub use config::{TlsClientConfig, TlsConfigError};
pub use identity::{TlsIdentity, TlsIdentityError};

// The public API speaks this crate's types, so a caller names the
// version this crate resolved instead of guessing it in its own.
pub use rustls;
