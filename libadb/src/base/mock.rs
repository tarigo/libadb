//! A transport that answers synchronously, so a future can be driven by
//! hand and dropped at an exact point — which a socket-backed test
//! cannot do.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use bytes::BytesMut;

use crate::base::channel::ChannelId;
use crate::base::connection::Connection;
use crate::base::protocol::command::Command;
use crate::base::protocol::packet::Packet;
use crate::base::protocol::{command, Checksum};

#[derive(Debug, PartialEq, Eq)]
pub struct MockError;

impl core::fmt::Display for MockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("mock transport error")
    }
}

impl embedded_io::Error for MockError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

/// A transport whose every operation completes at once, except for one
/// write that never does.
pub(crate) struct Mock {
    inbound: VecDeque<u8>,
    writes: Vec<Vec<u8>>,
    stall_write: Option<usize>,
    /// Reads that report `Pending` before any data comes back.
    slow_reads: usize,
    cancel_safe: bool,
}

impl Mock {
    pub(crate) fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            writes: Vec::new(),
            stall_write: None,
            slow_reads: 0,
            cancel_safe: true,
        }
    }

    pub(crate) fn feed(&mut self, pkt: &Packet) -> &mut Self {
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf, Checksum::Compute).unwrap();
        self.inbound.extend(buf.iter().copied());
        self
    }

    /// Park the next `n` reads once each before answering, so an
    /// interrupt can become ready while a read is in flight.
    pub(crate) fn slow_reads(&mut self, n: usize) -> &mut Self {
        self.slow_reads = n;
        self
    }

    /// Claim that dropping a read loses whatever the peer already sent,
    /// the way a USB bulk transfer does.
    pub(crate) fn loses_cancelled_reads(&mut self) -> &mut Self {
        self.cancel_safe = false;
        self
    }

    /// Stall the write with this index, counting from the first one the
    /// transport ever sees.
    pub(crate) fn stall_write(&mut self, index: usize) -> &mut Self {
        self.stall_write = Some(index);
        self
    }
}

impl embedded_io::ErrorType for Mock {
    type Error = MockError;
}

impl Mock {
    fn pull(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.inbound.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.inbound.pop_front().unwrap();
        }
        n
    }

    fn stalls_now(&self) -> bool {
        self.stall_write == Some(self.writes.len())
    }

    fn push(&mut self, buf: &[u8]) -> usize {
        self.writes.push(buf.to_vec());
        buf.len()
    }
}

impl embedded_io_async::Read for Mock {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockError> {
        if self.slow_reads > 0 {
            self.slow_reads -= 1;
            park_once().await;
        }
        Ok(self.pull(buf))
    }
}

impl crate::transport::ReadCancelSafety for Mock {
    fn read_cancel_safe(&self) -> bool {
        self.cancel_safe
    }
}

/// Report `Pending` once, waking immediately, then complete.
async fn park_once() {
    let mut done = false;
    core::future::poll_fn(move |cx| {
        if done {
            core::task::Poll::Ready(())
        } else {
            done = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await
}

impl embedded_io_async::Write for Mock {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MockError> {
        if self.stalls_now() {
            core::future::pending::<()>().await;
        }
        Ok(self.push(buf))
    }

    async fn flush(&mut self) -> Result<(), MockError> {
        Ok(())
    }
}

/// The same mock behind a shared handle, so both halves of a split
/// connection talk to one transport.
#[cfg(feature = "split")]
#[derive(Clone)]
pub(crate) struct SharedMock(alloc::sync::Arc<std::sync::Mutex<Mock>>);

#[cfg(feature = "split")]
impl SharedMock {
    fn new(mock: Mock) -> Self {
        Self(alloc::sync::Arc::new(std::sync::Mutex::new(mock)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Mock> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(feature = "split")]
impl embedded_io::ErrorType for SharedMock {
    type Error = MockError;
}

#[cfg(feature = "split")]
impl embedded_io_async::Read for SharedMock {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockError> {
        Ok(self.lock().pull(buf))
    }
}

#[cfg(feature = "split")]
impl embedded_io_async::Write for SharedMock {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MockError> {
        // The lock is released before the await: a stalled write must
        // not hold the other half out.
        if self.lock().stalls_now() {
            core::future::pending::<()>().await;
        }
        Ok(self.lock().push(buf))
    }

    async fn flush(&mut self) -> Result<(), MockError> {
        Ok(())
    }
}

#[cfg(feature = "split")]
impl crate::transport::Splittable for SharedMock {
    type ReadHalf = SharedMock;
    type WriteHalf = SharedMock;

    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), MockError> {
        Ok((self.clone(), self))
    }
}

/// Drive a future that only ever awaits the mock, and panic if it parks.
pub(crate) fn now<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("future never finished against the mock transport");
}

/// Poll `fut` a few times, then drop it where it stands.
pub(crate) fn abandon<F: Future>(fut: F) {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..8 {
        if fut.as_mut().poll(&mut cx).is_ready() {
            panic!("future finished; it was supposed to stall");
        }
    }
}

pub(crate) struct NoAuth;

impl crate::auth::Authenticator for NoAuth {
    type Error = ();

    async fn sign(&mut self, _token: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }

    fn public_key(&self) -> &[u8] {
        b"\0"
    }
}

pub(crate) fn cnxn() -> Packet {
    Packet::new(
        Command::Connect,
        command::ADB_VERSION,
        256 * 1024,
        b"device::features=shell_v2".to_vec(),
    )
}

pub(crate) fn okay(local_id: u32) -> Packet {
    Packet::new(Command::Ready, 42, local_id, Vec::new())
}

/// A connected `Connection` with one open channel, over a mock that
/// stalls on the write with the given index (counted after the two
/// writes the handshake and OPEN each take).
pub(crate) fn connected_with_channel(stall: Option<usize>) -> (Connection<Mock>, ChannelId) {
    let mut mock = Mock::new();
    mock.feed(&cnxn())
        .feed(&okay(1))
        .feed(&okay(1))
        .feed(&okay(1));
    // Handshake writes the CNXN header and banner; OPEN writes its own
    // header and destination.
    if let Some(index) = stall {
        mock.stall_write(4 + index);
    }
    let mut conn = now(Connection::<_>::connect(mock, NoAuth, &[])).unwrap();
    let ch = now(conn.open_channel(b"shell:\0")).unwrap();
    (conn, ch)
}

/// A split connection with one open channel, over a mock that stalls on
/// the write with the given index (counted from the first write after
/// the handshake and OPEN).
#[cfg(feature = "split")]
#[allow(clippy::type_complexity)]
pub(crate) fn split_with_channel(
    stall: Option<usize>,
) -> (
    crate::split::Reader<SharedMock, SharedMock>,
    crate::split::Writer<SharedMock>,
    ChannelId,
) {
    let mut mock = Mock::new();
    mock.feed(&cnxn()).feed(&okay(1)).feed(&okay(1));
    if let Some(index) = stall {
        mock.stall_write(4 + index);
    }
    let conn = now(Connection::<_>::connect(SharedMock::new(mock), NoAuth, &[])).unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    (reader, writer, ch)
}

pub(crate) fn wrte(local_id: u32, payload: &[u8]) -> Packet {
    Packet::new(Command::Write, 42, local_id, payload.to_vec())
}

/// A connection with one open channel and one WRTE waiting to be read,
/// with the transport configured after the handshake so that its
/// slowness only affects the read under test.
pub(crate) fn connected_for_select(
    configure: impl FnOnce(&mut Mock),
) -> (Connection<Mock>, ChannelId) {
    let mut mock = Mock::new();
    mock.feed(&cnxn()).feed(&okay(1));
    let mut conn = now(Connection::<_>::connect(mock, NoAuth, &[])).unwrap();
    let ch = now(conn.open_channel(b"shell:\0")).unwrap();
    let transport = conn.transport_mut();
    transport.feed(&wrte(1, b"hello"));
    configure(transport);
    (conn, ch)
}
