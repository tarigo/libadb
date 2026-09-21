//! `adb pair`: putting a key on a device that has never seen it.
//!
//! A key the device already trusts — one approved at a USB prompt —
//! needs none of this: [`Connection::connect_tls`](crate::Connection)
//! is accepted straight away, because adbd checks both against the same
//! store. Pairing is for a key it has never seen.
//!
//! The exchange runs on a port of its own, which the device shows on
//! its "Wireless debugging" pane along with a six-digit code, and which
//! is not the port a session later uses.
//!
//! # The shape of it
//!
//! 1. TLS 1.3, both sides presenting certificates neither of them
//!    checks. The device's is generated fresh for the pairing server.
//! 2. The password is *not* the six-digit code. It is that code's ASCII
//!    bytes with 64 bytes of TLS exporter output appended, under the
//!    label `adb-label\0`. Binding the password to the session is what
//!    stops the exchange being replayed elsewhere.
//! 3. One SPAKE2 message each way, 32 bytes apiece.
//! 4. One encrypted `PeerInfo` each way: the host sends its public key,
//!    the device answers with its GUID.
//!
//! A wrong code shows up only at step four, as a message that will not
//! authenticate.

mod aead;
mod client;
mod frame;
mod peer_info;
mod spake2;

pub use aead::AeadError;
pub use client::{pair, Paired, PairingError};
pub use frame::{FrameError, PacketType};
pub use peer_info::{PeerInfoError, PeerInfoType};
pub use spake2::{Role, Spake2, Spake2Error};
