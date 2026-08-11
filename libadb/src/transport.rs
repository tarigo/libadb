//! Transport abstractions for ADB connections.
//!
//! A transport is any type implementing `embedded_io_async::{Read, Write}`.
//! This module ships built-in TCP and USB transports and the [`Splittable`]
//! trait that powers [`Connection::split`](crate::Connection::split) for
//! concurrent read and write tasks on the same connection.
//!
//! # Submodules
//!
//! * [`tcp`] — `TokioTcp` / `SmolTcp` aliases (features `tokio` / `smol`).
//! * `nusb` — `UsbTransport` via `nusb` (feature `nusb`, also enabled
//!   by the `usb` convenience alias).
//! * `rusb` — `UsbTransport` via libusb/`rusb` (feature `rusb`; mutually
//!   exclusive with `nusb`).
//! * `usb` — backward-compatibility alias re-exporting the active USB
//!   backend under the pre-rename path.
//! * [`common`] — [`common::Transport`] enum wrapping either the active TCP
//!   transport or USB behind a single concrete type.
//! * [`any`] — [`any::AnyTransport`] and [`any::connect`] for URI-based
//!   dispatch between `tcp://` and `usb://` (features `tokio` or `smol`).
//! * [`split`] — the [`Splittable`] trait itself.

pub mod split;
pub mod tcp;

#[cfg(feature = "nusb")]
pub mod nusb;

#[cfg(feature = "rusb")]
pub mod rusb;

#[cfg(feature = "_usb")]
pub mod usb;

#[cfg(feature = "split")]
pub mod common;

#[cfg(any(feature = "tokio", feature = "smol"))]
pub mod any;

pub use split::Splittable;

/// ADB USB interface class (vendor-specific).
pub const ADB_CLASS: u8 = 0xFF;
/// ADB USB interface subclass.
pub const ADB_SUBCLASS: u8 = 0x42;
/// ADB USB interface protocol.
pub const ADB_PROTOCOL: u8 = 0x01;
