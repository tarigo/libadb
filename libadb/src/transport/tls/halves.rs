//! The halves a split [`MaybeTls`] becomes, plain or TLS, and the
//! engine the TLS ones share.

use alloc::boxed::Box;
use alloc::sync::Arc;
use std::sync::OnceLock;

use bytes::BytesMut;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use rustls::ClientConnection;

use super::error::TlsError;
use super::maybe_tls::{MaybeTls, State};
use super::session::{
    feed, harvest, send_queue, take_plaintext, write_plain, Inbound, Plain, TlsSession, QUEUE_LIMIT,
};
use crate::transport::{ReadCancelSafety, Splittable};

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

    /// Send `close_notify` and push it out: see [`MaybeTls::shutdown`].
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

impl<T: Splittable> ReadCancelSafety for TlsReadHalf<T> {
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

impl<T: Splittable> ReadCancelSafety for MaybeTlsRead<T> {
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
