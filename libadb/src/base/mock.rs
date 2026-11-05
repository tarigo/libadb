//! A transport that answers synchronously, so a future can be driven by
//! hand and dropped at an exact point — which a socket-backed test
//! cannot do.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use bytes::BytesMut;
use embedded_io::ErrorKind;

use crate::base::channel::ChannelId;
use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::protocol::{command, Checksum};

/// A transport failure of the kind a test asked for.
#[derive(Debug, PartialEq, Eq)]
pub struct MockError(ErrorKind);

impl core::fmt::Display for MockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("mock transport error")
    }
}

impl embedded_io::Error for MockError {
    fn kind(&self) -> ErrorKind {
        self.0
    }
}

/// A transport whose every operation completes at once, except for one
/// write that never does.
pub(crate) struct Mock {
    inbound: VecDeque<u8>,
    writes: Vec<Vec<u8>>,
    stall_write: Option<usize>,
    /// What every write fails with, once one has been asked for.
    write_failure: Option<ErrorKind>,
    /// The device's end a CLSE's header stalls on, if any does.
    stall_close_to: Option<u32>,
    /// What the next read fails with, ahead of anything queued.
    read_failure: Option<ErrorKind>,
    /// Have a read with nothing to hand back wait for more, rather than
    /// report the end of the stream.
    parks_when_drained: bool,
    /// The read waiting for more, to wake once there is some.
    parked_read: Option<Waker>,
    /// Reads that report `Pending` before any data comes back.
    slow_reads: usize,
    /// Writes that report `Pending` before they go through.
    #[cfg(feature = "split")]
    slow_writes: usize,
    cancel_safe: bool,
    /// Cap on what one read hands back; 0 means none.
    drip: usize,
}

impl Mock {
    pub(crate) fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            writes: Vec::new(),
            stall_write: None,
            write_failure: None,
            stall_close_to: None,
            read_failure: None,
            parks_when_drained: false,
            parked_read: None,
            slow_reads: 0,
            #[cfg(feature = "split")]
            slow_writes: 0,
            cancel_safe: true,
            drip: 0,
        }
    }

    /// Fail every write from now on with `kind`.
    pub(crate) fn fail_writes(&mut self, kind: ErrorKind) -> &mut Self {
        self.write_failure = Some(kind);
        self
    }

    /// Stall every write from now on.
    pub(crate) fn stall_writes(&mut self) -> &mut Self {
        self.stall_write = Some(self.writes.len());
        self
    }

    /// Park the next `n` writes once each before they go through, so
    /// that something can happen with one in flight.
    #[cfg(feature = "split")]
    pub(crate) fn slow_writes(&mut self, n: usize) -> &mut Self {
        self.slow_writes = n;
        self
    }

    /// Stall the write of a CLSE to the device's end `remote`, and let
    /// everything else through: no socket does this, but it tells a
    /// call that writes that packet from one that does not, which a
    /// transport stalled for good cannot.
    #[cfg(feature = "split")]
    pub(crate) fn stall_closes_to(&mut self, remote: u32) -> &mut Self {
        self.stall_close_to = Some(remote);
        self
    }

    /// Hand back at most `n` bytes a read, as TLS hands back a record at
    /// a time.
    pub(crate) fn drips(&mut self, n: usize) -> &mut Self {
        self.drip = n;
        self
    }

    pub(crate) fn feed(&mut self, pkt: &Packet) -> &mut Self {
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf, Checksum::Compute).unwrap();
        self.inbound.extend(buf.iter().copied());
        self.wake_parked_read();
        self
    }

    /// Queue `bytes` as they are, for what [`feed`](Self::feed) would not
    /// encode.
    #[cfg(feature = "split")]
    pub(crate) fn feed_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.inbound.extend(bytes);
        self.wake_parked_read();
        self
    }

    /// Fail the next read with `kind`, ahead of anything queued.
    #[cfg(feature = "split")]
    pub(crate) fn fail_next_read(&mut self, kind: ErrorKind) -> &mut Self {
        self.read_failure = Some(kind);
        self.wake_parked_read();
        self
    }

    /// Have a read with nothing to hand back wait for more, rather than
    /// report the end of the stream.
    #[cfg(feature = "split")]
    pub(crate) fn parks_when_drained(&mut self) -> &mut Self {
        self.parks_when_drained = true;
        self
    }

    /// End the stream, for a read waiting for more.
    #[cfg(feature = "split")]
    pub(crate) fn hang_up(&mut self) -> &mut Self {
        self.parks_when_drained = false;
        self.wake_parked_read();
        self
    }

    fn wake_parked_read(&mut self) {
        if let Some(read) = self.parked_read.take() {
            read.wake();
        }
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
        let cap = match self.drip {
            0 => buf.len(),
            drip => buf.len().min(drip),
        };
        let n = cap.min(self.inbound.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.inbound.pop_front().unwrap();
        }
        n
    }

    fn poll_pull(&mut self, cx: &Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, MockError>> {
        if let Some(kind) = self.read_failure.take() {
            return Poll::Ready(Err(MockError(kind)));
        }
        if self.inbound.is_empty() && self.parks_when_drained {
            self.parked_read = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(self.pull(buf)))
    }

    fn stalls_on(&self, buf: &[u8]) -> bool {
        let closes_to = |remote: u32| {
            let word =
                |at: usize| u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
            buf.len() == crate::base::protocol::MESSAGE_SIZE
                && word(0) == u32::from(Command::Close)
                && word(8) == remote
        };
        self.stall_write == Some(self.writes.len()) || self.stall_close_to.is_some_and(closes_to)
    }

    fn push(&mut self, buf: &[u8]) -> Result<usize, MockError> {
        if let Some(kind) = self.write_failure {
            return Err(MockError(kind));
        }
        self.writes.push(buf.to_vec());
        Ok(buf.len())
    }
}

impl embedded_io_async::Read for Mock {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockError> {
        if self.slow_reads > 0 {
            self.slow_reads -= 1;
            park_once().await;
        }
        core::future::poll_fn(|cx| self.poll_pull(cx, buf)).await
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
        if self.stalls_on(buf) {
            core::future::pending::<()>().await;
        }
        self.push(buf)
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
    /// Acknowledgements the split halves sent for `local_id`.
    pub(crate) fn acks_for(&self, local_id: u32) -> Vec<u32> {
        self.lock().acks_for(local_id)
    }

    /// Everything the split halves sent, in wire order.
    pub(crate) fn sent(&self) -> Vec<(Command, u32, u32, Vec<u8>)> {
        self.lock().sent()
    }

    /// Queue a packet for the reader, as the device would send it.
    pub(crate) fn feed(&self, pkt: &Packet) {
        self.lock().feed(pkt);
    }

    /// Fail every write from now on with `kind`.
    pub(crate) fn fail_writes(&self, kind: ErrorKind) {
        self.lock().fail_writes(kind);
    }

    /// Queue `bytes` as they are, for what [`feed`](Self::feed) would not
    /// encode.
    pub(crate) fn feed_bytes(&self, bytes: &[u8]) {
        self.lock().feed_bytes(bytes);
    }

    /// Fail the next read with `kind`, ahead of anything queued.
    pub(crate) fn fail_next_read(&self, kind: ErrorKind) {
        self.lock().fail_next_read(kind);
    }

    /// Have a read with nothing to hand back wait for more, rather than
    /// report the end of the stream.
    pub(crate) fn parks_when_drained(&self) {
        self.lock().parks_when_drained();
    }

    /// End the stream, for a read waiting for more.
    pub(crate) fn hang_up(&self) {
        self.lock().hang_up();
    }

    /// Stall every write from now on.
    pub(crate) fn stall_writes(&self) {
        self.lock().stall_writes();
    }

    /// Park the next `n` writes once each before they go through, so
    /// that something can happen with one in flight.
    pub(crate) fn slow_writes(&self, n: usize) {
        self.lock().slow_writes(n);
    }

    /// Stall the write of a CLSE to the device's end `remote`, and let
    /// everything else through.
    pub(crate) fn stall_closes_to(&self, remote: u32) {
        self.lock().stall_closes_to(remote);
    }

    pub(crate) fn new(mock: Mock) -> Self {
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
        core::future::poll_fn(|cx| self.lock().poll_pull(cx, buf)).await
    }
}

#[cfg(feature = "split")]
impl embedded_io_async::Write for SharedMock {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MockError> {
        // The lock is released before the await: a stalled write must
        // not hold the other half out.
        if self.lock().stalls_on(buf) {
            core::future::pending::<()>().await;
        }
        let slow = self.lock().slow_writes > 0;
        if slow {
            self.lock().slow_writes -= 1;
            park_once().await;
        }
        self.lock().push(buf)
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

impl Mock {
    /// Packets handed to the transport, rejoined from the header and
    /// payload writes each one takes.
    pub(crate) fn sent(&self) -> Vec<(Command, u32, u32, Vec<u8>)> {
        let mut stream: Vec<u8> = Vec::new();
        for w in &self.writes {
            stream.extend_from_slice(w);
        }
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 24 <= stream.len() {
            let word = |at: usize| {
                u32::from_le_bytes([stream[at], stream[at + 1], stream[at + 2], stream[at + 3]])
            };
            let command = Command::try_from(word(pos)).expect("valid command");
            let (arg0, arg1) = (word(pos + 4), word(pos + 8));
            let len = word(pos + 12) as usize;
            pos += 24;
            let payload = stream[pos..pos + len].to_vec();
            pos += len;
            out.push((command, arg0, arg1, payload));
        }
        out
    }

    /// Acknowledgements sent for `local_id`, as byte counts (zero for a
    /// plain OKAY).
    pub(crate) fn acks_for(&self, local_id: u32) -> Vec<u32> {
        self.sent()
            .into_iter()
            .filter(|(cmd, arg0, _, _)| *cmd == Command::Ready && *arg0 == local_id)
            .map(|(_, _, _, payload)| {
                if payload.len() >= 4 {
                    u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
                } else {
                    0
                }
            })
            .collect()
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

/// Why [`NoAuth`] never signs.
pub(crate) struct NoKey;

impl core::fmt::Display for NoKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no key")
    }
}

impl crate::auth::Authenticator for NoAuth {
    type Error = NoKey;

    async fn sign(&mut self, _token: &[u8]) -> Result<Vec<u8>, NoKey> {
        Err(NoKey)
    }

    fn public_key(&self) -> &[u8] {
        b"\0"
    }
}

/// Signs anything, with a signature no device would accept; enough for
/// a handshake whose device side is scripted.
pub(crate) struct Signs;

impl crate::auth::Authenticator for Signs {
    type Error = NoKey;

    fn sign(
        &mut self,
        _token: &[u8],
    ) -> impl core::future::Future<Output = Result<Vec<u8>, Self::Error>> {
        core::future::ready(Ok(alloc::vec![0xA5; 256]))
    }

    fn public_key(&self) -> &[u8] {
        b"QUJD signs@mock\0"
    }
}

/// Signs as [`Signs`] does, but keeps its key to itself: it only asks
/// whether the device trusts it already.
pub(crate) struct Withholds;

impl crate::auth::Authenticator for Withholds {
    type Error = NoKey;

    fn sign(
        &mut self,
        _token: &[u8],
    ) -> impl core::future::Future<Output = Result<Vec<u8>, Self::Error>> {
        core::future::ready(Ok(alloc::vec![0xA5; 256]))
    }

    fn public_key(&self) -> &[u8] {
        b"QUJD withholds@mock\0"
    }

    fn offer_public_key(&self) -> bool {
        false
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

/// What an Android 11+ device on the wireless-debugging port answers a
/// CNXN with: it will speak nothing but TLS from here on.
pub(crate) fn stls() -> Packet {
    Packet::new(
        Command::StartTls,
        crate::base::protocol::constant::STLS_VERSION,
        0,
        Vec::new(),
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
    let mut conn = now(Connection::connect(
        mock,
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let ch = now(conn.open_channel(b"shell:\0")).unwrap();
    (conn, ch)
}

/// A connection with a single channel slot to a device advertising
/// `features`, which answers the first OPEN and then sends `then`.
pub(crate) fn one_slot(features: &str, then: &[Packet]) -> Connection<Mock> {
    let mut mock = Mock::new();
    mock.feed(&cnxn_with(features)).feed(&okay(1));
    for pkt in then {
        mock.feed(pkt);
    }
    now(Connection::connect(
        mock,
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new().with_max_channels(1),
    ))
    .unwrap()
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
    let conn = now(Connection::connect(
        SharedMock::new(mock),
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    (reader, writer, ch)
}

/// A split connection with delayed-ack on, one channel whose OPEN
/// grants `budget` bytes, and `extra` packets queued behind it — the
/// grants the reader dispatches when polled.
#[cfg(feature = "split")]
#[allow(clippy::type_complexity)]
pub(crate) fn split_one_channel_delayed_ack(
    budget: u32,
    extra: &[Packet],
) -> (
    crate::split::Reader<SharedMock, SharedMock>,
    crate::split::Writer<SharedMock>,
    ChannelId,
    SharedMock,
) {
    let mut mock = Mock::new();
    mock.feed(&cnxn_with("shell_v2,delayed_ack"))
        .feed(&okay_with_budget(1, budget));
    for pkt in extra {
        mock.feed(pkt);
    }
    let transport = SharedMock::new(mock);
    let seen = transport.clone();
    let conn = now(Connection::connect(
        transport,
        NoAuth,
        HostBanner::Raw(b"host::features=shell_v2,delayed_ack"),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, writer) = conn.split().unwrap();
    let ch = now(reader.open_channel(b"shell:\0")).unwrap();
    (reader, writer, ch, seen)
}

pub(crate) fn cnxn_with(features: &str) -> Packet {
    Packet::new(
        Command::Connect,
        command::ADB_VERSION,
        256 * 1024,
        alloc::format!("device::features={features}").into_bytes(),
    )
}

/// OKAY answering an OPEN, carrying the initial send budget the device
/// grants us when delayed-ack is on.
pub(crate) fn okay_with_budget(local_id: u32, budget: u32) -> Packet {
    Packet::new(Command::Ready, 42, local_id, budget.to_le_bytes().to_vec())
}

pub(crate) fn wrte(local_id: u32, payload: &[u8]) -> Packet {
    Packet::new(Command::Write, 42, local_id, payload.to_vec())
}

/// The device closing our channel `local_id` from its end, 42.
pub(crate) fn clse(local_id: u32) -> Packet {
    Packet::new(Command::Close, 42, local_id, Vec::new())
}

/// The CLSE a device sends to take back its OPEN from `remote_id`: it
/// names no end of ours.
pub(crate) fn withdraw(remote_id: u32) -> Packet {
    Packet::new(Command::Close, remote_id, 0, Vec::new())
}

/// A connection with one open channel and one WRTE waiting to be read,
/// with the transport configured after the handshake so that its
/// slowness only affects the read under test.
pub(crate) fn connected_for_select(
    configure: impl FnOnce(&mut Mock),
) -> (Connection<Mock>, ChannelId) {
    let mut mock = Mock::new();
    mock.feed(&cnxn()).feed(&okay(1));
    let mut conn = now(Connection::connect(
        mock,
        NoAuth,
        HostBanner::Features(&[]),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let ch = now(conn.open_channel(b"shell:\0")).unwrap();
    let transport = conn.transport_mut();
    transport.feed(&wrte(1, b"hello"));
    configure(transport);
    (conn, ch)
}

/// A delayed-ack connection with two open channels, the second of which
/// nobody has read yet. `pushes` are queued for the transport to hand
/// over in order.
pub(crate) fn two_channels_delayed_ack(
    budget: u32,
    pushes: &[Packet],
) -> (Connection<Mock>, ChannelId, ChannelId) {
    let mut mock = Mock::new();
    mock.feed(&cnxn_with("shell_v2,delayed_ack"))
        .feed(&okay_with_budget(1, budget))
        .feed(&okay_with_budget(2, budget));
    for pkt in pushes {
        mock.feed(pkt);
    }
    let mut conn = now(Connection::connect(
        mock,
        NoAuth,
        HostBanner::Raw(b"host::features=shell_v2,delayed_ack"),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let a = now(conn.open_channel(b"shell:a\0")).unwrap();
    let b = now(conn.open_channel(b"shell:b\0")).unwrap();
    (conn, a, b)
}

/// A connection without delayed-ack, two open channels, and a config
/// whose watermark the caller picks.
pub(crate) fn two_channels_classic(
    config: ConnectionConfig,
    pushes: &[Packet],
) -> (Connection<Mock>, ChannelId, ChannelId) {
    let mut mock = Mock::new();
    mock.feed(&cnxn_with("shell_v2"))
        .feed(&okay(1))
        .feed(&okay(2));
    for pkt in pushes {
        mock.feed(pkt);
    }
    let mut conn = now(Connection::connect(
        mock,
        NoAuth,
        HostBanner::Raw(b"host::features=shell_v2"),
        config,
    ))
    .unwrap();
    let a = now(conn.open_channel(b"shell:a\0")).unwrap();
    let b = now(conn.open_channel(b"shell:b\0")).unwrap();
    (conn, a, b)
}

/// A split, delayed-ack connection with two channels; the returned
/// handle sees everything the halves write.
#[cfg(feature = "split")]
#[allow(clippy::type_complexity)]
pub(crate) fn split_two_channels_delayed_ack(
    pushes: &[Packet],
) -> (
    crate::split::Reader<SharedMock, SharedMock>,
    ChannelId,
    ChannelId,
    SharedMock,
) {
    let mut mock = Mock::new();
    mock.feed(&cnxn_with("shell_v2,delayed_ack"))
        .feed(&okay_with_budget(1, 64 * 1024))
        .feed(&okay_with_budget(2, 64 * 1024));
    for pkt in pushes {
        mock.feed(pkt);
    }
    let transport = SharedMock::new(mock);
    let seen = transport.clone();
    let conn = now(Connection::connect(
        transport,
        NoAuth,
        HostBanner::Raw(b"host::features=shell_v2,delayed_ack"),
        ConnectionConfig::new(),
    ))
    .unwrap();
    let (mut reader, _writer) = conn.split().unwrap();
    let a = now(reader.open_channel(b"shell:a\0")).unwrap();
    let b = now(reader.open_channel(b"shell:b\0")).unwrap();
    (reader, a, b, seen)
}
