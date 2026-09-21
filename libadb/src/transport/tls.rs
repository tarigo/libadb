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

#[cfg(feature = "tls")]
pub use self::inner::*;

#[cfg(feature = "tls")]
mod inner {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::future::Future;

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
        /// handshake.
        HandshakeClosed,
        /// TLS was asked of something that cannot do it: a USB
        /// transport, a session already started, or one left unusable
        /// by a handshake that failed.
        NotAvailable,
    }

    impl<E: core::fmt::Display> core::fmt::Display for TlsError<E> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "io: {e}"),
                Self::Tls(e) => write!(f, "tls: {e}"),
                Self::HandshakeClosed => f.write_str("tls: device closed during the handshake"),
                Self::NotAvailable => f.write_str("tls: not available on this transport"),
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
                Self::HandshakeClosed | Self::NotAvailable => None,
            }
        }
    }

    impl<E: embedded_io::Error> embedded_io::Error for TlsError<E> {
        fn kind(&self) -> embedded_io::ErrorKind {
            match self {
                Self::Io(e) => e.kind(),
                Self::Tls(_) | Self::HandshakeClosed => embedded_io::ErrorKind::Other,
                Self::NotAvailable => embedded_io::ErrorKind::Unsupported,
            }
        }
    }

    /// A transport that can put a TLS session on top of itself.
    pub trait StartTls: Read + Write {
        /// Start TLS 1.3 as the client and carry the handshake through.
        ///
        /// `pending` is ciphertext already taken off the wire by a
        /// reader above — the first records, if the device sent them on
        /// the heels of its `STLS`.
        ///
        /// A failure leaves the transport unusable: a socket whose
        /// handshake broke down has nothing to say afterwards.
        fn start_tls(
            &mut self,
            config: &TlsClientConfig,
            pending: &[u8],
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
    fn alert_means_rejection(alert: rustls::AlertDescription) -> bool {
        use rustls::AlertDescription as A;
        matches!(
            alert,
            A::CertificateRequired
                | A::BadCertificate
                | A::UnsupportedCertificate
                | A::CertificateRevoked
                | A::CertificateExpired
                | A::CertificateUnknown
                | A::UnknownCA
                | A::AccessDenied
                | A::DecryptError
                | A::HandshakeFailure
        )
    }

    impl<E> TlsError<E> {
        /// Whether this is a device refusing the key, rather than a
        /// connection that went wrong on its own.
        pub fn is_key_rejected(&self) -> bool {
            match self {
                Self::Tls(rustls::Error::AlertReceived(a)) => alert_means_rejection(*a),
                // Some adbd builds just close, with no alert at all.
                Self::HandshakeClosed => true,
                _ => false,
            }
        }
    }

    /// What a look at the plaintext side turned up.
    enum Plain {
        Got(usize),
        /// The peer closed, cleanly or otherwise.
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

    /// Hand rustls the ciphertext in `rx` and let it decrypt.
    fn feed(conn: &mut ClientConnection, rx: &mut BytesMut) -> Result<(), rustls::Error> {
        while !rx.is_empty() {
            let taken = match conn.read_tls(&mut &rx[..]) {
                Ok(0) => break,
                Ok(n) => n,
                // The plaintext buffer is full; the caller drains it
                // before coming back, so this is backpressure, not a
                // failure.
                Err(_) => break,
            };
            rx.advance(taken);
            conn.process_new_packets()?;
        }
        Ok(())
    }

    /// Take whatever plaintext is decrypted.
    fn take_plaintext(conn: &mut ClientConnection, buf: &mut [u8]) -> Plain {
        use std::io::Read as _;
        match conn.reader().read(buf) {
            Ok(0) => Plain::Eof,
            Ok(n) => Plain::Got(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Plain::Blocked,
            // A peer gone without `close_notify`. To the layer above that is
            // still the end of the stream.
            Err(_) => Plain::Eof,
        }
    }

    /// Build the engine and seed it with ciphertext already in hand.
    fn engine(
        config: &TlsClientConfig,
        pending: &[u8],
    ) -> Result<(Box<ClientConnection>, BytesMut), rustls::Error> {
        let conn =
            ClientConnection::new(Arc::clone(config.rustls()), config.server_name().clone())?;
        let mut rx = BytesMut::with_capacity(CHUNK);
        rx.extend_from_slice(pending);
        Ok((Box::new(conn), rx))
    }

    /// A TLS session over one transport, before anyone splits it.
    pub struct TlsSession<T> {
        inner: T,
        conn: Box<ClientConnection>,
        /// Ciphertext read off the wire and not yet decrypted. A field
        /// rather than a local, so a dropped read loses nothing.
        rx: BytesMut,
        /// Records produced and not yet written, already advanced past
        /// whatever the socket took. A dropped write resumes here
        /// instead of leaving half a record behind.
        tx: BytesMut,
        /// Where one socket read lands before it is committed to `rx`.
        scratch: Vec<u8>,
        eof: bool,
    }

    impl<T: Read + Write> TlsSession<T> {
        fn new(
            inner: T,
            config: &TlsClientConfig,
            pending: &[u8],
        ) -> Result<Self, TlsError<T::Error>> {
            let (conn, rx) = engine(config, pending).map_err(TlsError::Tls)?;
            Ok(Self {
                inner,
                conn,
                rx,
                tx: BytesMut::new(),
                scratch: vec![0u8; CHUNK],
                eof: false,
            })
        }

        /// Write out everything queued, resuming where a dropped write
        /// left off.
        async fn flush_tx(&mut self) -> Result<(), TlsError<T::Error>> {
            while !self.tx.is_empty() {
                let n = self.inner.write(&self.tx).await.map_err(TlsError::Io)?;
                if n == 0 {
                    return Err(TlsError::HandshakeClosed);
                }
                self.tx.advance(n);
            }
            self.inner.flush().await.map_err(TlsError::Io)
        }

        /// Read one chunk of ciphertext off the wire.
        async fn fill(&mut self) -> Result<(), TlsError<T::Error>> {
            // Into `scratch`, not `rx`: a read dropped mid-await must not
            // leave `rx` holding bytes that never arrived.
            let n = self
                .inner
                .read(&mut self.scratch)
                .await
                .map_err(TlsError::Io)?;
            if n == 0 {
                self.eof = true;
            } else {
                self.rx.extend_from_slice(&self.scratch[..n]);
            }
            Ok(())
        }

        /// Let rustls decrypt, pushing out any alert it raises.
        async fn advance(&mut self) -> Result<(), TlsError<T::Error>> {
            let outcome = feed(&mut self.conn, &mut self.rx);
            if let Err(e) = outcome {
                // The alert explaining the failure is queued now; the
                // peer deserves it even though we are about to give up.
                harvest(&mut self.conn, &mut self.tx);
                let _ = self.flush_tx().await;
                return Err(TlsError::Tls(e));
            }
            Ok(())
        }

        async fn handshake(&mut self) -> Result<(), TlsError<T::Error>> {
            while self.conn.is_handshaking() {
                harvest(&mut self.conn, &mut self.tx);
                self.flush_tx().await?;
                if !self.conn.is_handshaking() {
                    break;
                }
                if self.eof {
                    return Err(TlsError::HandshakeClosed);
                }
                self.fill().await?;
                self.advance().await?;
            }
            // The last flight is still queued at this point.
            harvest(&mut self.conn, &mut self.tx);
            self.flush_tx().await
        }

        /// Send `close_notify` and push it out.
        pub async fn shutdown(&mut self) -> Result<(), TlsError<T::Error>> {
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
                // Reading can owe the peer a record: a key update, or
                // the answer to a close_notify.
                harvest(&mut self.conn, &mut self.tx);
                self.flush_tx().await?;

                if self.eof {
                    return Ok(0);
                }
                self.fill().await?;
                self.advance().await?;
            }
        }
    }

    impl<T: Read + Write> Write for TlsSession<T> {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            use std::io::Write as _;
            if buf.is_empty() {
                return Ok(0);
            }
            let n =
                self.conn.writer().write(buf).map_err(|_| {
                    TlsError::Tls(rustls::Error::General("tls writer closed".into()))
                })?;
            harvest(&mut self.conn, &mut self.tx);
            self.flush_tx().await?;
            Ok(n)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
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

    impl<T: Read + Write> StartTls for MaybeTls<T> {
        async fn start_tls(
            &mut self,
            config: &TlsClientConfig,
            pending: &[u8],
        ) -> Result<(), Self::Error> {
            // `Broken` is the placeholder that lets the value move out
            // of `&mut self` without unsafe. It also happens to be the
            // truth if the handshake does not finish.
            let State::Plain(inner) = core::mem::replace(&mut self.state, State::Broken) else {
                return Err(TlsError::NotAvailable);
            };

            let mut session = TlsSession::new(inner, config, pending)?;
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
        /// A dropped TLS read loses nothing of its own: ciphertext and owed
        /// records both live in the session. What is left belongs to the
        /// transport underneath.
        fn read_cancel_safe(&self) -> bool {
            match &self.state {
                State::Plain(t) => t.read_cancel_safe(),
                State::Tls(s) => s.inner.read_cancel_safe(),
                State::Broken => false,
            }
        }
    }

    impl<T, U> StartTls for Transport<MaybeTls<T>, U>
    where
        T: Read + Write,
        U: Read + Write,
    {
        async fn start_tls(
            &mut self,
            config: &TlsClientConfig,
            pending: &[u8],
        ) -> Result<(), Self::Error> {
            match self {
                Self::Tcp(t) => t
                    .start_tls(config, pending)
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

    /// The write half of the socket together with what is still owed to
    /// it. The cursor is why a dropped write cannot tear a record in
    /// two: whoever takes the lock next carries on from the same place.
    struct OutHalf<WH> {
        half: WH,
        pending: BytesMut,
    }

    /// What both halves of a split session share.
    struct TlsShared<T: Splittable> {
        /// Only ever held across rustls' own work, never across an
        /// await on the socket. That is what keeps the two locks from
        /// forming a cycle.
        conn: async_lock::Mutex<Box<ClientConnection>>,
        out: async_lock::Mutex<OutHalf<T::WriteHalf>>,
    }

    impl<T: Splittable> TlsShared<T> {
        /// Append `records` to the queue and drain it into the socket.
        ///
        /// An empty `records` still drains, which is how a reader
        /// pushes out what an earlier, dropped write left behind.
        async fn write_records(&self, records: &[u8]) -> Result<(), TlsError<T::Error>> {
            let mut out = self.out.lock().await;
            out.pending.extend_from_slice(records);
            while !out.pending.is_empty() {
                let n = {
                    let OutHalf { half, pending } = &mut *out;
                    half.write(pending).await.map_err(TlsError::Io)?
                };
                if n == 0 {
                    return Err(TlsError::HandshakeClosed);
                }
                out.pending.advance(n);
            }
            out.half.flush().await.map_err(TlsError::Io)
        }
    }

    /// The read half of a TLS session.
    pub struct TlsReadHalf<T: Splittable> {
        inner: T::ReadHalf,
        rx: BytesMut,
        scratch: Vec<u8>,
        eof: bool,
        shared: Arc<TlsShared<T>>,
    }

    /// The write half of a TLS session.
    pub struct TlsWriteHalf<T: Splittable> {
        shared: Arc<TlsShared<T>>,
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
                // Step one: plaintext, if rustls already has some.
                let owed = {
                    let mut conn = self.shared.conn.lock().await;
                    match take_plaintext(&mut conn, buf) {
                        Plain::Got(n) => return Ok(n),
                        Plain::Eof => return Ok(0),
                        Plain::Blocked => {}
                    }
                    let mut owed = BytesMut::new();
                    harvest(&mut conn, &mut owed);
                    owed
                };

                // Step two: no lock on the engine while the socket runs.
                self.shared.write_records(&owed).await?;

                if self.eof {
                    return Ok(0);
                }
                let n = self
                    .inner
                    .read(&mut self.scratch)
                    .await
                    .map_err(TlsError::Io)?;
                if n == 0 {
                    self.eof = true;
                } else {
                    self.rx.extend_from_slice(&self.scratch[..n]);
                }

                // Step three: decrypt, and push out an alert if it went
                // wrong.
                let outcome = {
                    let mut conn = self.shared.conn.lock().await;
                    let outcome = feed(&mut conn, &mut self.rx);
                    let mut owed = BytesMut::new();
                    harvest(&mut conn, &mut owed);
                    (outcome, owed)
                };
                let (result, owed) = outcome;
                if !owed.is_empty() {
                    self.shared.write_records(&owed).await?;
                }
                result.map_err(TlsError::Tls)?;
            }
        }
    }

    impl<T: Splittable> Write for TlsWriteHalf<T> {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            use std::io::Write as _;
            if buf.is_empty() {
                return Ok(0);
            }
            let (n, records) = {
                let mut conn = self.shared.conn.lock().await;
                let n = conn.writer().write(buf).map_err(|_| {
                    TlsError::Tls(rustls::Error::General("tls writer closed".into()))
                })?;
                let mut records = BytesMut::new();
                harvest(&mut conn, &mut records);
                (n, records)
            };
            self.shared.write_records(&records).await?;
            Ok(n)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            let records = {
                let mut conn = self.shared.conn.lock().await;
                let mut records = BytesMut::new();
                harvest(&mut conn, &mut records);
                records
            };
            self.shared.write_records(&records).await
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
                        rx,
                        tx,
                        scratch,
                        eof,
                    } = session;
                    let (r, w) = inner.split().map_err(TlsError::Io)?;
                    let shared = Arc::new(TlsShared::<T> {
                        conn: async_lock::Mutex::new(conn),
                        out: async_lock::Mutex::new(OutHalf {
                            half: w,
                            pending: tx,
                        }),
                    });
                    let read = TlsReadHalf {
                        inner: r,
                        rx,
                        scratch,
                        eof,
                        shared: Arc::clone(&shared),
                    };
                    let write = TlsWriteHalf { shared };
                    Ok((MaybeTlsRead::Tls(read), MaybeTlsWrite::Tls(write)))
                }
                State::Broken => Err(TlsError::NotAvailable),
            }
        }
    }
}
