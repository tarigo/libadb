//! Transport-agnostic ADB protocol core.
//!
//! Runs the CNXN/AUTH handshake, multiplexes logical channels over a
//! single byte stream, and parses CNXN banner metadata. Contains no
//! runtime I/O — any type implementing `embedded_io_async::{Read, Write}`
//! can drive it. The service modules (`shell_v1`, `shell_v2`, `exec`,
//! `cmd`, `abb`, `logcat`, `sync`, `track_app`) live at the crate root
//! and build on top of these primitives.
//!
//! # Submodules
//!
//! * [`connection`] — [`Connection`](connection::Connection): the main
//!   entry point; handshake, `open` / `open_channel`, feature
//!   negotiation, `split` for full-duplex use.
//! * [`channel`] — [`Channel`](channel::Channel) handle,
//!   [`ChannelId`](channel::ChannelId), [`SelectResult`](channel::SelectResult)
//!   for multi-channel APIs.
//! * [`auth`] — [`Authenticator`](auth::Authenticator) trait plugged
//!   into the AUTH exchange (typically an RSA signer over
//!   `~/.android/adbkey`).
//! * [`device_banner`] — parsed `device::…` CNXN banner (properties and
//!   advertised features).
//! * [`error`] — [`Error`](error::Error) and its `Protocol` / `Auth` /
//!   `Sync` / `Decode` / `Logcat` sub-variants.
//! * [`protocol`] — wire-level constants, [`Command`](protocol::Command),
//!   [`Feature`](protocol::features::Feature), packet and message
//!   framing.

pub mod auth;
pub mod channel;
pub mod connection;

pub(crate) mod destination;
pub mod device_banner;
pub mod error;
#[cfg(test)]
pub(crate) mod mock;
pub(crate) mod protobuf;
pub mod protocol;
pub(crate) mod recv_buf;
pub(crate) mod wire;
