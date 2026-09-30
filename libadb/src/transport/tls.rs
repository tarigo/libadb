//! A transport that can start TLS on itself, for ADB's `STLS`.
//!
//! `MaybeTls` sits in the TCP slot of
//! [`Transport`](crate::transport::common::Transport), so a connection
//! keeps the same type whether or not the device asked for TLS. Before
//! `StartTls::start_tls` it passes bytes straight through; after it,
//! everything goes through `rustls`.
//!
//! The `rustls` engine is driven by hand over
//! [`embedded_io_async`] rather than through a runtime-specific adapter
//! such as `tokio-rustls`. At the point the upgrade happens all we hold
//! is a generic reader-writer, not a socket, and one hand-driven engine
//! serves every runtime this crate supports.

#[cfg(feature = "tls")]
pub use self::inner::*;

#[cfg(feature = "tls")]
mod inner {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::future::Future;
    use std::sync::OnceLock;

    use bytes::{Buf, BytesMut};
    use embedded_io::ErrorType;
    use embedded_io_async::{Read, Write};
    use rustls::ClientConnection;

    use crate::tls::TlsClientConfig;
    use crate::transport::common::Transport;
    use crate::transport::{ReadCancelSafety, Splittable};

    /// Landing zone for one socket read. A TLS record tops out a little
    /// over 16 KiB, so one of these swallows a whole record.
    const CHUNK: usize = 16 * 1024 + 512;

    /// How much sealed output a write leaves queued before the next one
    /// sends it first. Below this, writes only queue, so a packet's
    /// header and payload leave together on the flush that ends it.
    const QUEUE_LIMIT: usize = 64 * 1024;

    /// Why a TLS transport failed.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum TlsError<E> {
        /// The transport underneath failed.
        Io(E),
        /// The TLS session failed: a handshake, a record, or an alert
        /// the device sent.
        Tls(rustls::Error),
        /// The device closed the connection in the middle of the
        /// handshake. Our certificate only goes out once the handshake
        /// is over on our side, so the device had not seen the key.
        HandshakeClosed,
        /// The transport underneath took none of a write. An
        /// `embedded-io` writer may not do that with bytes on offer, so
        /// the connection is taken as gone, not as a device refusing
        /// anything.
        WriteZero,
        /// TLS was asked of something that cannot do it: a USB
        /// transport, a session already started, or one left unusable
        /// by a handshake that failed.
        NotAvailable,
        /// A write came after `shutdown`. rustls would still seal it and
        /// send it behind the `close_notify`, which the peer takes as the
        /// end of what we have to say.
        Closed,
    }

    impl<E: core::fmt::Display> core::fmt::Display for TlsError<E> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "io: {e}"),
                Self::Tls(e) => write!(f, "tls: {e}"),
                Self::HandshakeClosed => f.write_str("tls: device closed during the handshake"),
                Self::WriteZero => f.write_str("tls: the transport took none of a write"),
                Self::NotAvailable => f.write_str("tls: not available on this transport"),
                Self::Closed => f.write_str("tls: the session was already shut down"),
            }
        }
    }

    impl<E> core::error::Error for TlsError<E>
    where
        E: core::error::Error + 'static,
    {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Io(e) => Some(e),
                Self::Tls(e) => Some(e),
                Self::HandshakeClosed | Self::WriteZero | Self::NotAvailable | Self::Closed => None,
            }
        }
    }

    impl<E: embedded_io::Error> embedded_io::Error for TlsError<E> {
        fn kind(&self) -> embedded_io::ErrorKind {
            match self {
                Self::Io(e) => e.kind(),
                Self::Tls(_) | Self::HandshakeClosed => embedded_io::ErrorKind::Other,
                Self::WriteZero => embedded_io::ErrorKind::WriteZero,
                Self::NotAvailable => embedded_io::ErrorKind::Unsupported,
                Self::Closed => embedded_io::ErrorKind::BrokenPipe,
            }
        }
    }

    /// Keeps [`StartTls`] to this crate's transports.
    mod sealed {
        pub trait Sealed {}
    }

    /// A transport that can put a TLS session on top of itself.
    ///
    /// Sealed: only this crate's transports implement it, so a method
    /// can be added later without breaking anyone.
    pub trait StartTls: Read + Write + sealed::Sealed {
        /// Start TLS 1.3 as the client and carry the handshake through.
        ///
        /// The server says nothing before the client's hello, so there is
        /// no ciphertext a reader above could have taken off the wire
        /// first: the session starts from the socket as it stands.
        ///
        /// A failure leaves the transport unusable: a socket whose
        /// handshake broke down has nothing to say afterwards.
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

    /// Alerts a device sends when it will not have the key.
    ///
    /// adbd refuses from its certificate callback, which BoringSSL
    /// answers with `certificate_unknown`; the rest are the other
    /// certificate alerts a TLS stack might pick instead. Generic ones
    /// such as `handshake_failure` or `decrypt_error` stay out: they
    /// mean the handshake broke for some other reason, and calling that
    /// a refusal would send the user off to pair for nothing. So does
    /// `certificate_required`, which says no certificate arrived at all.
    fn alert_means_rejection(alert: rustls::AlertDescription) -> bool {
        use rustls::AlertDescription as A;
        matches!(
            alert,
            A::BadCertificate
                | A::UnsupportedCertificate
                | A::CertificateRevoked
                | A::CertificateExpired
                | A::CertificateUnknown
                | A::UnknownCA
                | A::AccessDenied
        )
    }

    impl<E> TlsError<E> {
        /// Whether this is a device refusing the key, rather than a
        /// connection that went wrong on its own.
        pub fn is_key_rejected(&self) -> bool {
            match self {
                Self::Tls(rustls::Error::AlertReceived(a)) => alert_means_rejection(*a),
                // Not `HandshakeClosed`: the key had not gone out yet. A
                // device that refuses by just closing does so after the
                // handshake, and the connect path names that on its own.
                _ => false,
            }
        }
    }

    /// What a look at the plaintext side turned up.
    enum Plain {
        Got(usize),
        /// The peer's `close_notify` has arrived, and everything before
        /// it has been read.
        Eof,
        /// Nothing decrypted yet.
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
    fn harvest(conn: &mut ClientConnection, out: &mut BytesMut) {
        while conn.wants_write() {
            if conn.write_tls(&mut Sink(out)).is_err() {
                break;
            }
        }
    }

    /// Hand rustls the ciphertext in `rx`; returns how much it took.
    ///
    /// rustls buffers incomplete records itself, so it takes all of `rx`
    /// unless the plaintext fills up first, and the callers drain that
    /// before they come here. Zero with bytes left over means it will
    /// take none: the peer's `close_notify` has arrived, and whatever
    /// follows it is not part of the session.
    fn feed(conn: &mut ClientConnection, rx: &mut BytesMut) -> Result<usize, rustls::Error> {
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
    fn take_plaintext(conn: &mut ClientConnection, buf: &mut [u8]) -> Plain {
        use std::io::Read as _;
        match conn.reader().read(buf) {
            Ok(0) => Plain::Eof,
            Ok(n) => Plain::Got(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Plain::Blocked,
            // rustls raises `UnexpectedEof` once told the stream ended
            // without a `close_notify`, which it never is here; were it
            // told, that would still be the end to the layer above. A
            // broken record never shows here: it fails in
            // `process_new_packets`.
            Err(_) => Plain::Eof,
        }
    }

    /// Ciphertext on its way in, for either kind of session.
    struct Inbound {
        /// Read off the wire and not yet decrypted. A field rather than a
        /// local, so a dropped read loses nothing.
        rx: BytesMut,
        /// Where one socket read lands before it is committed to `rx`.
        scratch: Vec<u8>,
        /// Whether the transport underneath has ended.
        eof: bool,
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
        async fn fill<R: Read>(&mut self, inner: &mut R) -> Result<(), TlsError<R::Error>> {
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
    async fn send_queue<W: Write>(
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
    fn write_plain<E>(conn: &mut ClientConnection, buf: &[u8]) -> Result<usize, TlsError<E>> {
        use std::io::Write as _;
        conn.writer()
            .write(buf)
            .map_err(|_| TlsError::Tls(rustls::Error::General("tls writer closed".into())))
    }

    /// Build the engine.
    fn engine(config: &TlsClientConfig) -> Result<Box<ClientConnection>, rustls::Error> {
        let conn =
            ClientConnection::new(Arc::clone(config.rustls()), config.server_name().clone())?;
        Ok(Box::new(conn))
    }

    /// A TLS session over one transport, before anyone splits it.
    pub(crate) struct TlsSession<T> {
        inner: T,
        conn: Box<ClientConnection>,
        inbound: Inbound,
        /// Records sealed and not yet written, already advanced past
        /// whatever the socket took, so a dropped call resumes here
        /// instead of leaving half a record behind. They go out on a
        /// flush, or once there are `QUEUE_LIMIT` of them.
        tx: BytesMut,
        /// The failure the session met, kept so that every call after it
        /// reports it too. Set before anything awaits, so a dropped call
        /// cannot take it along.
        failed: Option<rustls::Error>,
        /// Whether `shutdown` has queued `close_notify`.
        closed: bool,
    }

    impl<T: Read + Write> TlsSession<T> {
        fn new(inner: T, config: &TlsClientConfig) -> Result<Self, TlsError<T::Error>> {
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

        /// Once the session has failed, every call reports that. The alert
        /// for it goes out with the first write, flush or shutdown after,
        /// if the socket will take it.
        async fn failure(&mut self) -> Result<(), TlsError<T::Error>> {
            let Some(e) = self.failed.clone() else {
                return Ok(());
            };
            harvest(&mut self.conn, &mut self.tx);
            let _ = self.flush_tx().await;
            Err(TlsError::Tls(e))
        }

        async fn handshake(&mut self) -> Result<(), TlsError<T::Error>> {
            while self.conn.is_handshaking() {
                harvest(&mut self.conn, &mut self.tx);
                self.flush_tx().await?;
                // What is already in hand comes before the socket, and the
                // socket only once rustls has taken all of it. Reading on
                // while it takes none would pile up whatever the peer sends.
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
            // The last flight is still queued at this point.
            harvest(&mut self.conn, &mut self.tx);
            self.flush_tx().await
        }

        /// RFC 5705 exporter output for this session.
        fn export_keying_material(
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
            self.failure().await?;
            self.conn.send_close_notify();
            self.closed = true;
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
                        // What rustls will not take follows a `close_notify`.
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

    enum State<T: Read + Write> {
        Plain(T),
        Tls(TlsSession<T>),
        /// Held while the upgrade runs, and kept for good if it failed.
        Broken,
    }

    /// A transport that is plain now and may be TLS later.
    ///
    /// # Cancellation
    ///
    /// Reads lose nothing when dropped, as far as the transport
    /// underneath allows; see
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety). Nor do
    /// writes: over TLS, `write` seals what it takes into a queue and
    /// returns without waiting again, so a write dropped part way has
    /// committed nothing it did not report. The queue is what waits on
    /// the socket. It goes out on `flush`, or with a later write once it
    /// has grown to 64 KiB, as with any buffered writer; call `flush`
    /// when a message is done.
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
        pub fn is_plain(&self) -> bool {
            matches!(self.state, State::Plain(_))
        }

        /// Key material exported from the running session, as RFC 5705
        /// defines it.
        ///
        /// Pairing needs this: its password is the six-digit code with
        /// the exporter's output appended, which is what ties the
        /// exchange to the session it runs in.
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
        /// not done on drop, because dropping cannot await.
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
            // stays if the handshake fails. Anything else goes back untouched.
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
        /// Make the TCP half able to start TLS, without starting any.
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
        /// The failure the session met, kept so that every call after it
        /// reports it too. The reader sets it under `conn`, where a writer
        /// looks before it hands rustls anything, so none slips past.
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
    /// under *Cancellation*.
    pub struct TlsWriteHalf<T: Splittable> {
        half: T::WriteHalf,
        /// Records sealed and not yet written, advanced past whatever the
        /// socket took, so a dropped call resumes where it stopped.
        pending: BytesMut,
        /// Whether `shutdown` may have queued `close_notify`.
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
                // Plaintext first, under the engine lock alone.
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
                        // What rustls will not take follows a `close_notify`.
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
        Plain(T::ReadHalf),
        Tls(TlsReadHalf<T>),
    }

    /// The write half of a [`MaybeTls`], plain or encrypted.
    ///
    /// Encrypted, writes queue and `flush` sends; see [`MaybeTls`] under
    /// *Cancellation*.
    pub enum MaybeTlsWrite<T: Splittable> {
        Plain(T::WriteHalf),
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
        /// [`MaybeTls::shutdown`] for a transport that has been split.
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
}
