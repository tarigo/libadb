//! Low-level ADB (Android Debug Bridge) wire-protocol library.
//!
//! Talks to a device directly over TCP or USB — no `adbd` fork/exec,
//! no `adb` binary, no platform-tools dependency.
//!
//! The core protocol layer is `no_std + alloc`. Any runtime feature
//! (`tokio`, `smol`, `nusb`, `rusb`) implicitly enables `std` — the
//! split Reader/Writer pair and USB backends rely on std sync
//! primitives. For pure `no_std + alloc` builds, use the crate with
//! `default-features = false` and bring your own `embedded_io_async`
//! transport.
//!
//! For a C ABI, see the companion crate `libadb-ffi`.
//!
//! # Feature flags
//!
//! | Flag    | Enables                                                                    |
//! |---------|----------------------------------------------------------------------------|
//! | `tokio` | TCP transport over `tokio::net::TcpStream` (default)                       |
//! | `smol`  | TCP transport over `smol::net::TcpStream`; mutually exclusive with `tokio` |
//! | `nusb`  | USB transport via `nusb` (pure-Rust); mutually exclusive with `rusb`       |
//! | `rusb`  | USB transport via `rusb` (libusb); mutually exclusive with `nusb`          |
//! | `usb`   | Convenience alias enabling the default USB backend (`nusb`)                |
//! | `split` | [`split`] Reader/Writer pair with no bundled runtime; pulls in `std`. Implied by every feature above |
//!
//! # Quick start
//!
//! ```ignore
//! use libadb::shell::v2;
//! use libadb::{Connection, Feature, TokioTcp};
//!
//! let tcp = tokio::net::TcpStream::connect("127.0.0.1:5555").await?;
//! let transport = TokioTcp::new(tcp);
//!
//! // `auth` is a user-supplied `libadb::auth::Authenticator` —
//! // typically an RSA signer reading `~/.android/adbkey`. A complete
//! // `AdbKeyAuth` using the `rsa` crate lives in `examples/`.
//! let mut conn = Connection::<_>::connect(transport, auth, &[Feature::ShellV2]).await?;
//!
//! let mut rx = [0u8; 64 * 1024];
//! let out = v2::exec(&mut conn, "getprop ro.product.model", &mut rx).await?;
//! println!("{}", core::str::from_utf8(&out.stdout)?);
//! ```
//!
//! # Memory budget
//!
//! Every connection is opened with a [`ConnectionConfig`] that bounds
//! what the library may allocate:
//!
//! * `max_payload` — advertised to the device in CNXN, so it caps the
//!   size of any single inbound packet (and hence the receive buffer);
//! * `initial_ack_bytes` — delayed-ACK credit granted per channel;
//! * `max_rx_per_channel` — fuse on data buffered for a channel nobody
//!   is reading.
//!
//! [`ConnectionConfig::new`] reproduces `adb`'s desktop behaviour (1 MiB
//! packets, 32 MiB credit, unbounded buffering).
//! [`ConnectionConfig::embedded`] fits a microcontroller:
//!
//! ```ignore
//! let conn = Connection::<_>::connect_with_config(
//!     transport, auth, &[Feature::ShellV2], ConnectionConfig::embedded(),
//! ).await?;
//! ```
//!
//! On a microcontroller-sized heap the default config is unusable: one
//! 64 KiB WRTE can exhaust it, because the packet has to be buffered
//! whole. `embedded()` caps packets at 8 KiB, and adbd honours the
//! advertised limit.
//!
//! # Services
//!
//! * [`shell::v1`] — legacy `shell:` (interleaved stdout/stderr, no exit code)
//! * [`shell::v2`] — framed stdout/stderr/exit, optional PTY
//! * [`exec`]     — binary-clean `exec:` (no PTY, no exit code)
//! * [`cmd`]      — `abb_exec` / `abb` / `shell:cmd` fallback chain
//! * [`abb`]      — Android Binder Bridge (Android 10+)
//! * [`logcat`]   — parsed binary logcat stream
//! * [`sync`]     — file transfer (`STAT` / `LIST` / `SEND` / `RECV`, v1 + v2)
//! * [`track_app`] — streaming debuggable/profileable process list
//!
//! # Transports
//!
//! `TokioTcp`, `SmolTcp`, `UsbTransport`, or any user type implementing
//! `embedded_io_async::{Read, Write}` plus [`Splittable`]. For concurrent
//! read and write tasks on the same connection, see
//! [`Connection::split`] and the resulting `Reader` / `Writer` pair.
//!
//! # Status
//!
//! Pre-1.0. Public API is subject to semver-breaking changes before 1.0.

#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "tokio", feature = "smol"))]
compile_error!("features `tokio` and `smol` are mutually exclusive; enable only one");

#[cfg(all(feature = "nusb", feature = "rusb"))]
compile_error!("features `nusb` and `rusb` are mutually exclusive; enable only one");

#[cfg(all(feature = "_usb", not(any(feature = "nusb", feature = "rusb"))))]
compile_error!("feature `_usb` is internal; enable `nusb` (or the `usb` alias) or `rusb` instead");

extern crate alloc;

#[cfg(feature = "split")]
extern crate std;

pub mod abb;
pub mod base;
pub mod cmd;
pub mod exec;
pub mod logcat;
pub mod shell;
#[cfg(feature = "split")]
pub mod split;
pub mod sync;
pub mod track_app;
pub mod transport;
pub mod uri;

// Structural: expose private `base::*` submodules as top-level modules.
pub use base::{auth, channel, connection, device_banner, error, protocol};

// Core types used in every non-trivial caller.
pub use base::connection::{Connection, ConnectionConfig};
pub use base::error::{Error, ProtocolError};
pub use base::protocol::features::{Feature, DEFAULT_HOST_FEATURES};
pub use transport::Splittable;

#[cfg(feature = "split")]
pub use split::{Reader, Writer};

#[cfg(feature = "tokio")]
pub use transport::tcp::TokioTcp;

#[cfg(feature = "smol")]
pub use transport::tcp::SmolTcp;

#[cfg(feature = "nusb")]
pub use transport::nusb::UsbTransport;

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
pub use transport::rusb::UsbTransport;

#[cfg(feature = "_usb")]
pub use transport::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};

/// Common vocabulary for `use libadb::prelude::*;`.
pub mod prelude {
    pub use crate::{
        Connection, ConnectionConfig, Error, Feature, ProtocolError, Splittable,
        DEFAULT_HOST_FEATURES,
    };

    #[cfg(feature = "split")]
    pub use crate::{Reader, Writer};

    #[cfg(feature = "tokio")]
    pub use crate::TokioTcp;

    #[cfg(feature = "smol")]
    pub use crate::SmolTcp;

    #[cfg(feature = "_usb")]
    pub use crate::UsbTransport;
}
