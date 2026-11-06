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

const CHUNK: usize = 16 * 1024 + 512;

pub(super) const QUEUE_LIMIT: usize = 64 * 1024;

pub(super) enum Plain {
    Got(usize),
    Eof,
    Blocked,
}

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

pub(super) fn harvest(conn: &mut ClientConnection, out: &mut BytesMut) {
    while conn.wants_write() {
        if conn.write_tls(&mut Sink(out)).is_err() {
            break;
        }
    }
}

pub(super) fn feed(conn: &mut ClientConnection, rx: &mut BytesMut) -> Result<usize, rustls::Error> {
    let start = rx.len();
    while !rx.is_empty() {
        let taken = match conn.read_tls(&mut &rx[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Other => break,
            Err(e) => return Err(rustls::Error::General(alloc::format!("{e}"))),
        };
        rx.advance(taken);
        conn.process_new_packets()?;
    }
    Ok(start - rx.len())
}

pub(super) fn take_plaintext(conn: &mut ClientConnection, buf: &mut [u8]) -> Plain {
    use std::io::Read as _;
    match conn.reader().read(buf) {
        Ok(0) => Plain::Eof,
        Ok(n) => Plain::Got(n),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Plain::Blocked,
        Err(_) => Plain::Eof,
    }
}

pub(super) struct Inbound {
    pub(super) rx: BytesMut,
    scratch: Vec<u8>,
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

    pub(super) async fn fill<R: Read>(&mut self, inner: &mut R) -> Result<(), TlsError<R::Error>> {
        let n = inner.read(&mut self.scratch).await.map_err(TlsError::Io)?;
        if n == 0 {
            self.eof = true;
        } else {
            self.rx.extend_from_slice(&self.scratch[..n]);
        }
        Ok(())
    }
}

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

pub(super) struct TlsSession<T> {
    pub(super) inner: T,
    pub(super) conn: Box<ClientConnection>,
    pub(super) inbound: Inbound,
    pub(super) tx: BytesMut,
    pub(super) failed: Option<rustls::Error>,
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

    async fn flush_tx(&mut self) -> Result<(), TlsError<T::Error>> {
        send_queue(&mut self.inner, &mut self.tx).await?;
        self.inner.flush().await.map_err(TlsError::Io)
    }

    fn advance(&mut self) -> Result<usize, TlsError<T::Error>> {
        feed(&mut self.conn, &mut self.inbound.rx).map_err(|e| {
            self.failed = Some(e.clone());
            TlsError::Tls(e)
        })
    }

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
            if !self.inbound.rx.is_empty() {
                match self.advance() {
                    Ok(0) => return Err(TlsError::HandshakeClosed),
                    Ok(_) => continue,
                    Err(_) => return self.failure().await,
                }
            }
            if self.inbound.eof {
                return Err(TlsError::HandshakeClosed);
            }
            self.inbound.fill(&mut self.inner).await?;
        }
        harvest(&mut self.conn, &mut self.tx);
        self.flush_tx().await
    }

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

    pub async fn shutdown(&mut self) -> Result<(), TlsError<T::Error>> {
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
            if let Some(e) = &self.failed {
                return Err(TlsError::Tls(e.clone()));
            }

            if !self.inbound.rx.is_empty() {
                match self.advance() {
                    Ok(0) => return Ok(0),
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
