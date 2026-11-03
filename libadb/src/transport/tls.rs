//! A transport that can start TLS on itself, for ADB's `STLS`.
//!
//! [`MaybeTls`] sits in the TCP slot of
//! [`Transport`], so a connection
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
mod session;

pub use error::TlsError;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use std::sync::OnceLock;

use bytes::BytesMut;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use rustls::ClientConnection;

use crate::tls::TlsClientConfig;
use crate::transport::common::Transport;
use crate::transport::{ReadCancelSafety, Splittable};
use session::{
    feed, harvest, send_queue, take_plaintext, write_plain, Inbound, Plain, TlsSession, QUEUE_LIMIT,
};

mod sealed {
    pub trait Sealed {}
}

/// A transport that can put a TLS session on top of itself.
///
/// It is what [`Connection::connect_tls`](crate::Connection::connect_tls)
/// asks of its transport: a [`MaybeTls`], or a
/// [`Transport`] whose TCP side
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
    /// [`Transport`] each comes
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

enum State<T: Read + Write> {
    Plain(T),
    Tls(TlsSession<T>),
    /// Held while the upgrade runs, and kept for good if it failed or
    /// was dropped part way: the socket goes with the session.
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
/// Reads lose nothing when dropped, as far as the transport
/// underneath allows; see
/// [`ReadCancelSafety`]. Nor do
/// writes: over TLS, `write` seals what it takes into a queue and
/// returns without waiting again, so a write dropped part way has
/// committed nothing it did not report. The queue is what waits on
/// the socket. It goes out on `flush`, or with a later write once it
/// has grown to 64 KiB, as with any buffered writer; call `flush`
/// when a message is done. A dropped `flush` leaves the rest queued
/// for the next one. After a split nothing else sends it: the read
/// half never writes, so a reader waiting on the reply waits until
/// the write half writes or flushes again.
///
/// [`start_tls`](StartTls::start_tls) is the exception: it is not
/// cancel-safe.
pub struct MaybeTls<T: Read + Write> {
    state: State<T>,
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
    /// Not required — a device is content with a plain FIN — and
    /// not done on drop, because dropping cannot await. It leaves
    /// the transport underneath open; a write to the session after it
    /// fails with [`TlsError::Closed`]. On a session that has already
    /// failed it sends the alert for that failure instead, if the
    /// socket takes it, and returns the failure.
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
        // `Broken` stands in while the value is out of `&mut self`, and
        // stays if the handshake fails or this future is dropped.
        // Anything else goes back untouched.
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
            // adbd never offers STLS over USB.
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

impl<T: Read + Write, U> Transport<T, U> {
    /// Wrap a TCP transport in [`MaybeTls`] so that it can start TLS
    /// later, starting none now. A USB transport passes through as it
    /// is: adbd never offers TLS there, and `start_tls` on it fails
    /// with [`TlsError::NotAvailable`], wrapped in `TransportError::Tcp`
    /// as every TLS error is.
    pub fn tls_ready(self) -> Transport<MaybeTls<T>, U> {
        match self {
            Self::Tcp(t) => Transport::Tcp(MaybeTls::plain(t)),
            Self::Usb(u) => Transport::Usb(u),
        }
    }
}

/// What both halves of a split session share: the engine, and the
/// failure it met.
///
/// Each half takes `conn` only while rustls works, never across a
/// wait on the socket, so neither can hold the other up.
struct TlsShared {
    conn: async_lock::Mutex<Box<ClientConnection>>,
    /// The failure the session met, kept so that every later call
    /// reports it too; only a write after `shutdown` reports `Closed`
    /// instead. The reader sets it under `conn`, where a writer looks
    /// before it hands rustls anything, so none slips past.
    failed: OnceLock<rustls::Error>,
}

/// The read half of a TLS session.
pub struct TlsReadHalf<T: Splittable> {
    inner: T::ReadHalf,
    inbound: Inbound,
    shared: Arc<TlsShared>,
}

/// The write half of a TLS session.
///
/// Writes queue and `flush` sends, as for [`MaybeTls`]; see there
/// under *Cancellation*. Only this half sends: what a dropped `flush`
/// leaves waits for its next write or flush.
pub struct TlsWriteHalf<T: Splittable> {
    half: T::WriteHalf,
    /// Records sealed and not yet written, advanced past whatever the
    /// socket took, so a dropped call resumes where it stopped.
    pending: BytesMut,
    /// Whether `shutdown` has been called. Writes are refused from
    /// then on, as the `close_notify` may already be queued.
    closed: bool,
    shared: Arc<TlsShared>,
}

impl<T: Splittable> ErrorType for TlsReadHalf<T> {
    type Error = TlsError<T::Error>;
}

impl<T: Splittable> ErrorType for TlsWriteHalf<T> {
    type Error = TlsError<T::Error>;
}

impl<T: Splittable> Read for TlsReadHalf<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // Plaintext first.
            {
                let mut conn = self.shared.conn.lock().await;
                match take_plaintext(&mut conn, buf) {
                    Plain::Got(n) => return Ok(n),
                    Plain::Eof => return Ok(0),
                    Plain::Blocked => {}
                }
            }
            // What decrypted ahead of a failure is read before it.
            if let Some(e) = self.shared.failed.get() {
                return Err(TlsError::Tls(e.clone()));
            }

            // Decrypt what is in hand before going back to the socket, or
            // the tail of a closed stream is lost as a clean end of file.
            if !self.inbound.rx.is_empty() {
                let fed = {
                    let mut conn = self.shared.conn.lock().await;
                    // Kept under `conn`, where the writer looks. The alert
                    // rustls raises stays queued in the engine for the
                    // writer to carry: nothing on the read side writes.
                    feed(&mut conn, &mut self.inbound.rx).inspect_err(|e| {
                        let _ = self.shared.failed.set(e.clone());
                    })
                };
                match fed {
                    // A safeguard: `take_plaintext` above reports a
                    // `close_notify` first.
                    Ok(0) => return Ok(0),
                    // A failure is kept, and reported once what decrypted
                    // ahead of it has been read.
                    Ok(_) | Err(_) => continue,
                }
            }

            if self.inbound.eof {
                return Ok(0);
            }
            self.inbound.fill(&mut self.inner).await?;
        }
    }
}

impl<T: Splittable> TlsWriteHalf<T> {
    /// Run `f` on the engine and queue every record it, and anything
    /// before it, produced.
    ///
    /// Once the session has failed, `f` does not run: what gets queued
    /// is the alert for the failure, and the failure is the answer.
    async fn queue<R>(
        &mut self,
        f: impl FnOnce(&mut ClientConnection) -> R,
    ) -> Result<R, rustls::Error> {
        let mut conn = self.shared.conn.lock().await;
        let result = match self.shared.failed.get() {
            Some(e) => Err(e.clone()),
            None => Ok(f(&mut conn)),
        };
        harvest(&mut conn, &mut self.pending);
        result
    }

    /// Write out the queue and flush the half underneath, resuming
    /// where a dropped call stopped.
    async fn drain(&mut self) -> Result<(), TlsError<T::Error>> {
        send_queue(&mut self.half, &mut self.pending).await?;
        self.half.flush().await.map_err(TlsError::Io)
    }

    /// [`queue`](Self::queue) what `f` produces and send it all. A
    /// failed session sends the alert for its failure, if the socket
    /// takes it, and answers with the failure either way.
    async fn push_with<R>(
        &mut self,
        f: impl FnOnce(&mut ClientConnection) -> R,
    ) -> Result<R, TlsError<T::Error>> {
        let result = self.queue(f).await;
        let drained = self.drain().await;
        match result {
            Ok(result) => drained.map(|()| result),
            Err(e) => Err(TlsError::Tls(e)),
        }
    }

    /// Send `close_notify` and push it out.
    ///
    /// Not required — a device is content with a plain FIN — and
    /// not done on drop, because dropping cannot await. Without it a
    /// peer cannot tell a connection we closed from one cut short.
    ///
    /// It leaves the transport underneath open, and a write after it
    /// fails with [`TlsError::Closed`]. On a session that has already
    /// failed it sends the alert for that failure instead, if the
    /// socket takes it, and returns the failure.
    pub async fn shutdown(&mut self) -> Result<(), TlsError<T::Error>> {
        // Up front: a shutdown dropped part way may already have
        // queued the `close_notify`, and nothing may follow it.
        self.closed = true;
        self.push_with(|conn| conn.send_close_notify()).await
    }
}

impl<T: Splittable> Write for TlsWriteHalf<T> {
    /// Seals `buf` into the queue, as [`MaybeTls`]'s `write` does.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.closed {
            return Err(TlsError::Closed);
        }
        if self.pending.len() >= QUEUE_LIMIT {
            send_queue(&mut self.half, &mut self.pending).await?;
        }
        match self.queue(|conn| write_plain(conn, buf)).await {
            Ok(written) => written,
            // The alert for the failure is queued; it goes out now, if
            // the socket takes it.
            Err(e) => {
                let _ = self.drain().await;
                Err(TlsError::Tls(e))
            }
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.push_with(|_| ()).await
    }
}

impl<T> ReadCancelSafety for TlsReadHalf<T>
where
    T: Splittable,
    T::ReadHalf: ReadCancelSafety,
{
    fn read_cancel_safe(&self) -> bool {
        self.inner.read_cancel_safe()
    }
}

/// The read half of a [`MaybeTls`], plain or encrypted.
pub enum MaybeTlsRead<T: Splittable> {
    /// No TLS was started: the plain transport's read half.
    Plain(T::ReadHalf),
    /// The read half of the running TLS session.
    Tls(TlsReadHalf<T>),
}

/// The write half of a [`MaybeTls`], plain or encrypted.
///
/// Encrypted, writes queue and `flush` sends; see [`MaybeTls`] under
/// *Cancellation*.
pub enum MaybeTlsWrite<T: Splittable> {
    /// No TLS was started: the plain transport's write half.
    Plain(T::WriteHalf),
    /// The write half of the running TLS session.
    Tls(TlsWriteHalf<T>),
}

impl<T: Splittable> ErrorType for MaybeTlsRead<T> {
    type Error = TlsError<T::Error>;
}

impl<T: Splittable> ErrorType for MaybeTlsWrite<T> {
    type Error = TlsError<T::Error>;
}

impl<T: Splittable> Read for MaybeTlsRead<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Plain(t) => t.read(buf).await.map_err(TlsError::Io),
            Self::Tls(t) => t.read(buf).await,
        }
    }
}

impl<T: Splittable> MaybeTlsWrite<T> {
    /// Send `close_notify`, if there is a session to close.
    ///
    /// [`MaybeTls::shutdown`] for a transport that has been split,
    /// and [`TlsWriteHalf::shutdown`] underneath.
    pub async fn shutdown(&mut self) -> Result<(), TlsError<T::Error>> {
        match self {
            Self::Plain(_) => Ok(()),
            Self::Tls(t) => t.shutdown().await,
        }
    }
}

impl<T: Splittable> Write for MaybeTlsWrite<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Plain(t) => t.write(buf).await.map_err(TlsError::Io),
            Self::Tls(t) => t.write(buf).await,
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Plain(t) => t.flush().await.map_err(TlsError::Io),
            Self::Tls(t) => t.flush().await,
        }
    }
}

impl<T> ReadCancelSafety for MaybeTlsRead<T>
where
    T: Splittable,
    T::ReadHalf: ReadCancelSafety,
{
    fn read_cancel_safe(&self) -> bool {
        match self {
            Self::Plain(t) => t.read_cancel_safe(),
            Self::Tls(t) => t.read_cancel_safe(),
        }
    }
}

impl<T: Splittable> Splittable for MaybeTls<T> {
    type ReadHalf = MaybeTlsRead<T>;
    type WriteHalf = MaybeTlsWrite<T>;

    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        match self.state {
            State::Plain(t) => {
                let (r, w) = t.split().map_err(TlsError::Io)?;
                Ok((MaybeTlsRead::Plain(r), MaybeTlsWrite::Plain(w)))
            }
            State::Tls(session) => {
                let TlsSession {
                    inner,
                    conn,
                    inbound,
                    tx,
                    failed,
                    closed,
                } = session;
                let (r, w) = inner.split().map_err(TlsError::Io)?;
                let shared = Arc::new(TlsShared {
                    conn: async_lock::Mutex::new(conn),
                    failed: failed.map(OnceLock::from).unwrap_or_default(),
                });
                let read = TlsReadHalf {
                    inner: r,
                    inbound,
                    shared: Arc::clone(&shared),
                };
                let write = TlsWriteHalf {
                    half: w,
                    pending: tx,
                    closed,
                    shared,
                };
                Ok((MaybeTlsRead::Tls(read), MaybeTlsWrite::Tls(write)))
            }
            State::Broken => Err(TlsError::NotAvailable),
        }
    }
}
