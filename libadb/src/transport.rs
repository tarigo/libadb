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
//! * `runtime` — the [`Runtime`](runtime::Runtime) trait and its `Tokio`
//!   / `Smol` markers, so both runtimes can be compiled in at once.
//! * `nusb` — `UsbTransport` and the [`UsbBackend`] marker `Nusb`
//!   (feature `nusb`, also enabled by the `usb` convenience alias).
//! * `rusb` — the same via libusb (feature `rusb`). Both backends can be
//!   compiled in at once; pick one per call site through [`UsbBackend`].
//! * [`common`] — [`common::Transport`], a TCP-or-USB enum parameterised
//!   over both halves, and [`common::NoUsb`] for builds with no backend.
//! * [`any`] — [`any::AnyTransport`] and [`any::connect`] for URI-based
//!   dispatch between `tcp://` and `usb://` (features `tokio` or `smol`).
//! * [`split`] — the [`Splittable`] trait itself.

pub mod split;
pub mod tcp;

#[cfg(any(feature = "tokio", feature = "smol"))]
pub mod runtime;

#[cfg(feature = "nusb")]
pub mod nusb;

#[cfg(feature = "rusb")]
pub mod rusb;

#[cfg(feature = "split")]
pub mod common;

#[cfg(any(feature = "tokio", feature = "smol"))]
pub mod any;

pub use split::Splittable;

/// A USB backend: the way to obtain a USB transport from a
/// [`UsbSelector`](crate::uri::UsbSelector).
///
/// Implemented by the zero-sized markers `nusb::Nusb` and `rusb::Rusb`,
/// and by [`common::NoUsb`] for builds without USB. Choosing a backend
/// is a type argument rather than a feature, so enabling both features
/// compiles and each call site says which one it wants.
pub trait UsbBackend {
    /// Transport this backend produces.
    type Transport: embedded_io_async::Read + embedded_io_async::Write;
    /// Why opening a device failed.
    type Error: core::fmt::Display;

    /// Enumerate, match `selector`, and claim the device's ADB interface.
    ///
    /// Blocking: enumeration and claiming are synchronous in both
    /// backends. Callers on an async runtime should offload it.
    fn connect_by_selector(
        selector: crate::uri::UsbSelector<'_>,
    ) -> Result<Self::Transport, Self::Error>;
}

/// ADB USB interface class (vendor-specific).
pub const ADB_CLASS: u8 = 0xFF;
/// ADB USB interface subclass.
pub const ADB_SUBCLASS: u8 = 0x42;
/// ADB USB interface protocol.
pub const ADB_PROTOCOL: u8 = 0x01;
