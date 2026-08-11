//! Backward-compatibility alias for the active USB backend under the
//! pre-0.2 `transport::usb` path. Prefer the backend-specific modules
//! `transport::nusb` / `transport::rusb` or the top-level re-exports
//! on the crate root.

#[cfg(feature = "nusb")]
pub use super::nusb::*;

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
pub use super::rusb::*;

#[cfg(feature = "_usb")]
pub use super::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};
