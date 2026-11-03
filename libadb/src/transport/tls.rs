//! A transport that can start TLS on itself, for ADB's `STLS`.
//!
//! [`MaybeTls`] sits in the TCP slot of
//! [`Transport`](crate::transport::common::Transport), so a connection
//! keeps the same type whether or not the device asked for TLS. Before
//! [`StartTls::start_tls`] it passes bytes straight through; after it,
//! everything goes through `rustls`.
//!
//! The `rustls` engine is driven by hand over
//! [`embedded_io_async`] rather than through a runtime-specific adapter
//! such as `tokio-rustls`. At the point the upgrade happens all we hold
//! is a generic reader-writer, not a socket, and one hand-driven engine
//! serves every runtime this crate supports.

mod error;
mod halves;
mod maybe_tls;
mod session;

pub use error::TlsError;
pub use halves::{MaybeTlsRead, MaybeTlsWrite, TlsReadHalf, TlsWriteHalf};
pub use maybe_tls::MaybeTls;

use core::future::Future;

use embedded_io_async::{Read, Write};

use crate::tls::TlsClientConfig;

mod sealed {
    pub trait Sealed {}
}

/// A transport that can put a TLS session on top of itself.
///
/// It is what [`Connection::connect_tls`](crate::Connection::connect_tls)
/// asks of its transport: a [`MaybeTls`], or a
/// [`Transport`](crate::transport::common::Transport) whose TCP side
/// is one, as
/// [`tls_ready`](crate::transport::common::Transport::tls_ready)
/// makes it.
///
/// Sealed: only this crate's transports implement it, so a method
/// can be added later without breaking anyone.
pub trait StartTls: Read + Write + sealed::Sealed {
    /// Start TLS 1.3 as the client and carry the handshake through.
    ///
    /// The session starts from the socket as it stands: call this
    /// straight after the `STLS` exchange, with nothing read past it.
    ///
    /// # Errors
    ///
    /// [`TlsError::NotAvailable`] on USB, or on a transport that is
    /// no longer plain, which is left as it was. Otherwise
    /// [`TlsError::HandshakeClosed`] if the device hangs up during
    /// the handshake, [`TlsError::Tls`] if `rustls` fails it or will
    /// not start one, and [`TlsError::Io`] or [`TlsError::WriteZero`]
    /// from the socket. Through a
    /// [`Transport`](crate::transport::common::Transport) each comes
    /// wrapped in `TransportError::Tcp`.
    ///
    /// # Cancellation
    ///
    /// Not cancel-safe. A failure other than `NotAvailable`, or
    /// dropping the future before it completes, takes the socket
    /// with it: every read, write, flush and split after that
    /// returns [`TlsError::NotAvailable`].
    fn start_tls(
        &mut self,
        config: &TlsClientConfig,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Whether `error` is the device refusing the key we offered.
    ///
    /// TLS 1.3 tells a client nothing when the server rejects its
    /// certificate: the handshake finishes locally and the refusal
    /// arrives as an alert on the first read. Without this, that
    /// reads as an ordinary transport failure.
    fn is_key_rejected(error: &Self::Error) -> bool;
}
