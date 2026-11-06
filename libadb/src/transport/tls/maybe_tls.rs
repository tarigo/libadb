use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::error::TlsError;
use super::session::TlsSession;
use super::{sealed, StartTls};
use crate::tls::TlsClientConfig;
use crate::transport::common::Transport;
use crate::transport::ReadCancelSafety;

pub(super) enum State<T: Read + Write> {
    Plain(T),
    Tls(TlsSession<T>),
    Broken,
}

/// A transport that is plain now and may be TLS later.
///
/// Wrap the socket with [`plain`](Self::plain) and hand it to
/// [`Connection::connect_tls`](crate::Connection::connect_tls), which
/// starts TLS only if the device asks for it; `pairing::pair` takes
/// one too.
/// [`Transport::tls_ready`](crate::transport::common::Transport::tls_ready)
/// does the wrapping for the TCP-or-USB enum.
///
/// Once `rustls` rejects what the device sends in a running session,
/// every later read, write, flush and shutdown returns that same
/// [`TlsError::Tls`], except that a write after
/// [`shutdown`](Self::shutdown) is refused with [`TlsError::Closed`].
/// What decrypted ahead of the failure is still read first.
///
/// # Cancellation
///
/// Reads lose nothing when dropped, as far as the transport underneath
/// allows: see [`ReadCancelSafety`]. Nor do writes: over TLS, `write`
/// seals what it takes into a queue and returns without waiting again,
/// so a write dropped part way has committed nothing it did not report.
/// The queue goes out on `flush`, or with a later write once it has
/// grown to 64 KiB, as with any buffered writer; call `flush` when a
/// message is done. A dropped `flush` leaves the rest queued for the
/// next one. After a split the read half never writes, so a reader
/// waiting on the reply waits until the write half writes or flushes
/// again.
///
/// [`start_tls`](StartTls::start_tls) is the exception: it is not
/// cancel-safe.
pub struct MaybeTls<T: Read + Write> {
    pub(super) state: State<T>,
}

impl<T: Read + Write> MaybeTls<T> {
    /// Wrap a transport, starting no TLS.
    pub fn plain(inner: T) -> Self {
        Self {
            state: State::Plain(inner),
        }
    }

    /// Whether a TLS session is running.
    pub fn is_tls(&self) -> bool {
        matches!(self.state, State::Tls(_))
    }

    /// Whether bytes still go out in the clear.
    ///
    /// Both this and [`is_tls`](Self::is_tls) are false once a
    /// handshake that failed or was dropped has taken the socket.
    pub fn is_plain(&self) -> bool {
        matches!(self.state, State::Plain(_))
    }

    /// Key material exported from the running session, as RFC 5705
    /// defines it.
    ///
    /// Pairing needs this: its password is the pairing code with the
    /// exporter's output appended, which is what ties the exchange to
    /// the session it runs in.
    ///
    /// # Errors
    ///
    /// [`TlsError::NotAvailable`] unless a session is running;
    /// [`TlsError::Tls`] if `rustls` refuses the export.
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), TlsError<T::Error>> {
        match &self.state {
            State::Tls(s) => s
                .export_keying_material(out, label, context)
                .map_err(TlsError::Tls),
            State::Plain(_) | State::Broken => Err(TlsError::NotAvailable),
        }
    }

    /// Send `close_notify`, if there is a session to close.
    ///
    /// Not required, as a device is content with a plain FIN, and not
    /// done on drop, because dropping cannot await. Without it a peer
    /// cannot tell a connection we closed from one cut short.
    ///
    /// It leaves the transport underneath open; a write to the session
    /// after it fails with [`TlsError::Closed`]. On a session that has
    /// already failed it sends the alert for that failure instead, if
    /// the socket takes it, and returns the failure.
    pub async fn shutdown(&mut self) -> Result<(), TlsError<T::Error>> {
        match &mut self.state {
            State::Tls(s) => s.shutdown().await,
            State::Plain(_) | State::Broken => Ok(()),
        }
    }
}

impl<T: Read + Write> ErrorType for MaybeTls<T> {
    type Error = TlsError<T::Error>;
}

impl<T: Read + Write> Read for MaybeTls<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match &mut self.state {
            State::Plain(t) => t.read(buf).await.map_err(TlsError::Io),
            State::Tls(s) => s.read(buf).await,
            State::Broken => Err(TlsError::NotAvailable),
        }
    }
}

impl<T: Read + Write> Write for MaybeTls<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match &mut self.state {
            State::Plain(t) => t.write(buf).await.map_err(TlsError::Io),
            State::Tls(s) => s.write(buf).await,
            State::Broken => Err(TlsError::NotAvailable),
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match &mut self.state {
            State::Plain(t) => t.flush().await.map_err(TlsError::Io),
            State::Tls(s) => s.flush().await,
            State::Broken => Err(TlsError::NotAvailable),
        }
    }
}

impl<T: Read + Write> sealed::Sealed for MaybeTls<T> {}

impl<T: Read + Write> StartTls for MaybeTls<T> {
    async fn start_tls(&mut self, config: &TlsClientConfig) -> Result<(), Self::Error> {
        let inner = match core::mem::replace(&mut self.state, State::Broken) {
            State::Plain(inner) => inner,
            other => {
                self.state = other;
                return Err(TlsError::NotAvailable);
            }
        };

        let mut session = TlsSession::new(inner, config)?;
        session.handshake().await?;
        self.state = State::Tls(session);
        Ok(())
    }

    fn is_key_rejected(error: &Self::Error) -> bool {
        error.is_key_rejected()
    }
}

impl<T> ReadCancelSafety for MaybeTls<T>
where
    T: Read + Write + ReadCancelSafety,
{
    /// A dropped TLS read loses nothing of its own: the ciphertext it
    /// took and any failure it met both live in the session, set down
    /// before anything awaits. What is left belongs to the transport
    /// underneath.
    fn read_cancel_safe(&self) -> bool {
        match &self.state {
            State::Plain(t) => t.read_cancel_safe(),
            State::Tls(s) => s.inner.read_cancel_safe(),
            State::Broken => false,
        }
    }
}

impl<T, U> sealed::Sealed for Transport<MaybeTls<T>, U>
where
    T: Read + Write,
    U: Read + Write,
{
}

impl<T, U> StartTls for Transport<MaybeTls<T>, U>
where
    T: Read + Write,
    U: Read + Write,
{
    async fn start_tls(&mut self, config: &TlsClientConfig) -> Result<(), Self::Error> {
        match self {
            Self::Tcp(t) => t
                .start_tls(config)
                .await
                .map_err(crate::transport::common::TransportError::Tcp),
            Self::Usb(_) => Err(crate::transport::common::TransportError::Tcp(
                TlsError::NotAvailable,
            )),
        }
    }

    fn is_key_rejected(error: &Self::Error) -> bool {
        match error {
            crate::transport::common::TransportError::Tcp(e) => e.is_key_rejected(),
            crate::transport::common::TransportError::Usb(_) => false,
        }
    }
}
