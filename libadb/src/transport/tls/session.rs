//! The rustls engine driven by hand, and [`TlsSession`], one TLS
//! session over a transport before anyone splits it.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use bytes::{Buf, BytesMut};
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use rustls::ClientConnection;

use super::error::TlsError;
use crate::tls::TlsClientConfig;

/// Landing zone for one socket read. A TLS record tops out a little
/// over 16 KiB, so one of these swallows a whole record.
const CHUNK: usize = 16 * 1024 + 512;

/// Once this many bytes of sealed records wait in the queue, the next
/// write sends them before it seals its own. Below that, writes only
/// queue, and the flush that ends a packet sends all of it at once.
pub(super) const QUEUE_LIMIT: usize = 64 * 1024;

/// What a look at the plaintext side turned up.
pub(super) enum Plain {
    Got(usize),
    /// The peer's `close_notify` has arrived, and everything before
    /// it has been read.
    Eof,
    /// No plaintext waiting, and no `close_notify` either.
    Blocked,
}

/// Somewhere for `write_tls` to put records.
struct Sink<'a>(&'a mut BytesMut);

impl std::io::Write for Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Move every record rustls has ready into `out`.
pub(super) fn harvest(conn: &mut ClientConnection, out: &mut BytesMut) {
    while conn.wants_write() {
        if conn.write_tls(&mut Sink(out)).is_err() {
            break;
        }
    }
}

/// Hand rustls the ciphertext in `rx`; returns how much it took. That
/// is none only once a `close_notify` has arrived, which the callers
/// hear of from `take_plaintext` first, so their arms for zero are a
/// safeguard.
///
/// Nothing here writes. A KeyUpdate from the peer may ask for ours,
/// but rustls keeps the answer until our next record goes out, which
/// is all RFC 8446 section 4.6.3 asks; only a failure queues an alert.
pub(super) fn feed(conn: &mut ClientConnection, rx: &mut BytesMut) -> Result<usize, rustls::Error> {
    let start = rx.len();
    while !rx.is_empty() {
        let taken = match conn.read_tls(&mut &rx[..]) {
            Ok(0) => break,
            Ok(n) => n,
            // Backpressure: the plaintext is full, and the caller
            // drains it and comes back.
            Err(e) if e.kind() == std::io::ErrorKind::Other => break,
            // Anything else is for good. A handshake message too big
            // to buffer is refused this way, and would be refused on
            // every call after.
            Err(e) => return Err(rustls::Error::General(alloc::format!("{e}"))),
        };
        rx.advance(taken);
        conn.process_new_packets()?;
    }
    Ok(start - rx.len())
}

/// Take whatever plaintext is decrypted.
///
/// rustls sees the end of the session only as a `close_notify`. The
/// end of the stream underneath never reaches it: `feed` hands it
/// ciphertext and nothing else, and the callers watch for that end
/// themselves.
pub(super) fn take_plaintext(conn: &mut ClientConnection, buf: &mut [u8]) -> Plain {
    use std::io::Read as _;
    match conn.reader().read(buf) {
        Ok(0) => Plain::Eof,
        Ok(n) => Plain::Got(n),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Plain::Blocked,
        // `UnexpectedEof`, which only a stream end fed to rustls could
        // raise. A broken record fails in `process_new_packets`.
        Err(_) => Plain::Eof,
    }
}

/// Ciphertext on its way in, for either kind of session.
pub(super) struct Inbound {
    /// Read off the wire and not yet decrypted. A field rather than a
    /// local, so a dropped read loses nothing.
    pub(super) rx: BytesMut,
    /// Where one socket read lands before it is committed to `rx`.
    scratch: Vec<u8>,
    /// Whether the transport underneath has ended.
    pub(super) eof: bool,
}

impl Inbound {
    fn new() -> Self {
        Self {
            rx: BytesMut::with_capacity(CHUNK),
            scratch: vec![0u8; CHUNK],
            eof: false,
        }
    }

    /// Read one chunk of ciphertext off the wire.
    pub(super) async fn fill<R: Read>(&mut self, inner: &mut R) -> Result<(), TlsError<R::Error>> {
        // Into `scratch`, not `rx`: a read dropped mid-await must not
        // leave `rx` holding bytes that never arrived.
        let n = inner.read(&mut self.scratch).await.map_err(TlsError::Io)?;
        if n == 0 {
            self.eof = true;
        } else {
            self.rx.extend_from_slice(&self.scratch[..n]);
        }
        Ok(())
    }
}

/// Write out `queue`, resuming where a dropped call left off.
pub(super) async fn send_queue<W: Write>(
    w: &mut W,
    queue: &mut BytesMut,
) -> Result<(), TlsError<W::Error>> {
    while !queue.is_empty() {
        let n = w.write(queue).await.map_err(TlsError::Io)?;
        if n == 0 {
            return Err(TlsError::WriteZero);
        }
        queue.advance(n);
    }
    Ok(())
}

/// Hand rustls plaintext to seal; returns how much it took.
pub(super) fn write_plain<E>(
    conn: &mut ClientConnection,
    buf: &[u8],
) -> Result<usize, TlsError<E>> {
    use std::io::Write as _;
    conn.writer()
        .write(buf)
        .map_err(|_| TlsError::Tls(rustls::Error::General("tls writer closed".into())))
}

fn engine(config: &TlsClientConfig) -> Result<Box<ClientConnection>, rustls::Error> {
    let conn = ClientConnection::new(Arc::clone(config.rustls()), config.server_name().clone())?;
    Ok(Box::new(conn))
}

/// A TLS session over one transport, before anyone splits it.
pub(super) struct TlsSession<T> {
    pub(super) inner: T,
    pub(super) conn: Box<ClientConnection>,
    pub(super) inbound: Inbound,
    /// Records sealed and not yet written, already advanced past
    /// whatever the socket took, so a dropped call resumes here
    /// instead of leaving half a record behind. They go out on a
    /// flush, or with the next write once they come to `QUEUE_LIMIT`
    /// bytes.
    pub(super) tx: BytesMut,
    /// The failure the session met, kept so that every later call
    /// reports it too; only a write after `shutdown` reports `Closed`
    /// instead. Set before anything awaits, so a dropped call cannot
    /// take it along.
    pub(super) failed: Option<rustls::Error>,
    /// Whether `shutdown` has been called. Writes are refused from
    /// then on.
    pub(super) closed: bool,
}

impl<T: Read + Write> TlsSession<T> {
    pub(super) fn new(inner: T, config: &TlsClientConfig) -> Result<Self, TlsError<T::Error>> {
        let conn = engine(config).map_err(TlsError::Tls)?;
        Ok(Self {
            inner,
            conn,
            inbound: Inbound::new(),
            tx: BytesMut::new(),
            failed: None,
            closed: false,
        })
    }

    /// Write out everything queued and flush the transport, resuming
    /// where a dropped call left off.
    async fn flush_tx(&mut self) -> Result<(), TlsError<T::Error>> {
        send_queue(&mut self.inner, &mut self.tx).await?;
        self.inner.flush().await.map_err(TlsError::Io)
    }

    /// Let rustls decrypt what is in hand; returns how much it took.
    ///
    /// A failure is kept for good. The alert rustls raises for it stays
    /// queued in the engine for the next write, flush or shutdown to
    /// carry: sending it from here would hold the caller up behind the
    /// socket.
    fn advance(&mut self) -> Result<usize, TlsError<T::Error>> {
        feed(&mut self.conn, &mut self.inbound.rx).map_err(|e| {
            self.failed = Some(e.clone());
            TlsError::Tls(e)
        })
    }

    /// Once the session has failed, a write, flush or shutdown reports
    /// that, and the first of them sends the alert for it, if the
    /// socket will take it.
    async fn failure(&mut self) -> Result<(), TlsError<T::Error>> {
        let Some(e) = self.failed.clone() else {
            return Ok(());
        };
        harvest(&mut self.conn, &mut self.tx);
        let _ = self.flush_tx().await;
        Err(TlsError::Tls(e))
    }

    pub(super) async fn handshake(&mut self) -> Result<(), TlsError<T::Error>> {
        while self.conn.is_handshaking() {
            harvest(&mut self.conn, &mut self.tx);
            self.flush_tx().await?;
            // Ciphertext in hand goes to rustls before the socket is
            // read again. Mid-handshake rustls fails rather than refuse
            // input, so the arm for zero is a safeguard.
            if !self.inbound.rx.is_empty() {
                match self.advance() {
                    Ok(0) => return Err(TlsError::HandshakeClosed),
                    Ok(_) => continue,
                    // Nothing writes after a failed handshake, so the
                    // alert goes out now.
                    Err(_) => return self.failure().await,
                }
            }
            if self.inbound.eof {
                return Err(TlsError::HandshakeClosed);
            }
            self.inbound.fill(&mut self.inner).await?;
        }
        // Our last flight is still inside rustls at this point.
        harvest(&mut self.conn, &mut self.tx);
        self.flush_tx().await
    }

    /// RFC 5705 exporter output for this session.
    pub(super) fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), rustls::Error> {
        self.conn
            .export_keying_material(out, label, context)
            .map(|_| ())
    }

    /// Send `close_notify` and push it out.
    pub async fn shutdown(&mut self) -> Result<(), TlsError<T::Error>> {
        // Up front, as in the split half, so that a write after this is
        // refused however it ends, a failed session included.
        self.closed = true;
        self.failure().await?;
        self.conn.send_close_notify();
        harvest(&mut self.conn, &mut self.tx);
        self.flush_tx().await
    }
}

impl<T: Read + Write> ErrorType for TlsSession<T> {
    type Error = TlsError<T::Error>;
}

impl<T: Read + Write> Read for TlsSession<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match take_plaintext(&mut self.conn, buf) {
                Plain::Got(n) => return Ok(n),
                Plain::Eof => return Ok(0),
                Plain::Blocked => {}
            }
            // What decrypted ahead of a failure is read before it.
            if let Some(e) = &self.failed {
                return Err(TlsError::Tls(e.clone()));
            }

            // Decrypt what is in hand before going back to the socket, or
            // the tail of a closed stream is lost as a clean end of file.
            // Nothing here writes: what is queued is the writer's to send.
            if !self.inbound.rx.is_empty() {
                match self.advance() {
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

impl<T: Read + Write> Write for TlsSession<T> {
    /// Seals `buf` into the queue; nothing awaits after that, so a
    /// write dropped anywhere has committed nothing it did not report.
    /// What earlier writes queued goes out first once there is
    /// `QUEUE_LIMIT` of it, and otherwise waits for a flush.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.closed {
            return Err(TlsError::Closed);
        }
        self.failure().await?;
        if self.tx.len() >= QUEUE_LIMIT {
            send_queue(&mut self.inner, &mut self.tx).await?;
        }
        let n = write_plain(&mut self.conn, buf)?;
        harvest(&mut self.conn, &mut self.tx);
        Ok(n)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.failure().await?;
        harvest(&mut self.conn, &mut self.tx);
        self.flush_tx().await
    }
}
