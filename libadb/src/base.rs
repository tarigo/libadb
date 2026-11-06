//! Transport-agnostic ADB protocol core.
//!
//! Runs the CNXN/AUTH handshake, multiplexes logical channels over a
//! single byte stream, and parses CNXN banner metadata. Contains no
//! runtime I/O — any type implementing `embedded_io_async::{Read, Write}`
//! can drive it. The service modules (`shell::v1`, `shell::v2`, `exec`,
//! `cmd`, `abb`, `logcat`, `sync`, `reverse`, `track_app`) live at the
//! crate root and build on top of these primitives, as does the crate's
//! [`Error`](crate::Error).
//!
//! # Submodules
//!
//! * [`connection`] — [`Connection`](connection::Connection): the main
//!   entry point; handshake, `open` / `open_channel`, feature
//!   negotiation, `split` for full-duplex use.
//! * [`channel`] — [`Channel`](channel::Channel) handle,
//!   [`ChannelId`](channel::ChannelId), [`SelectResult`](channel::SelectResult)
//!   for multi-channel APIs.
//! * [`session`] — [`Session`](session::Session), what the service
//!   modules open their channels on: a `Connection` or a split `Writer`;
//!   and [`ServiceChannel`](session::ServiceChannel), its open, read and
//!   close, which the split `Reader` offers too.
//! * [`auth`] — [`Authenticator`](auth::Authenticator) trait plugged
//!   into the AUTH exchange (typically an RSA signer over
//!   `~/.android/adbkey`).
//! * [`device_banner`] — parsed `device::…` CNXN banner (properties and
//!   advertised features).
//! * [`error`] — [`Error`](crate::Error) and its `Protocol` / `Auth` /
//!   `Sync` / `Reverse` / `Decode` / `Logcat` sub-variants. The module
//!   lives at the crate root now and is re-exported here.
//! * [`protocol`] — wire-level constants, [`Command`](protocol::Command),
//!   [`Feature`](protocol::features::Feature), packet and message
//!   framing.
//!
//! The rest is private to the crate:
//!
//! * `channel_table` — every channel's slot, and where a packet from the
//!   device lands among them;
//! * `slot` — one channel's entry in it: its state, what it has buffered,
//!   and the flow control both ways;
//! * `send_queue` — the order concurrent writers on one channel take its
//!   credit in;
//! * `ids` — the ids a channel goes by on the wire, one per end;
//! * `incoming` — channels the device opened, waiting for a verdict;
//! * `negotiated` — what the handshake settled for the life of a
//!   connection;
//! * `wire` — sending and receiving whole packets over the transport,
//!   and the flag a half-written one leaves set;
//! * `destination` — building the NUL-terminated service strings an
//!   OPEN carries;
//! * `recv_buf` — the receive buffer `sync` and `track_app` parse their
//!   replies from;
//! * `protobuf` — the protobuf reading `track-app` needs;
//! * `decimal` — a `u32` in ASCII decimal without `core::fmt`, for the
//!   numbers `sync` and `shell::v2` send as text.

pub mod auth;
pub mod channel;
pub(crate) mod channel_table;
pub mod connection;

pub(crate) mod decimal;
pub(crate) mod destination;
pub mod device_banner;
pub(crate) mod ids;
pub(crate) mod incoming;
#[cfg(test)]
pub(crate) mod mock;
pub(crate) mod negotiated;
pub(crate) mod protobuf;
pub mod protocol;
pub(crate) mod recv_buf;
pub(crate) mod send_queue;
pub mod session;
pub(crate) mod slot;
pub(crate) mod wire;

pub use crate::error;
