extern crate std;

use super::*;
use crate::base::protocol::command::Command;
use crate::base::protocol::Checksum;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::vec::Vec;

std::thread_local! {
    /// Bytes `Staged::new` has zeroed on this thread, for the tests
    /// that pin how often a packet is staged.
    pub(crate) static ZEROED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[derive(Debug)]
struct MockErr;

impl embedded_io::Error for MockErr {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

/// Hands out queued bytes, filling as much of the caller's buffer as
/// it can, and counts how many times it was asked.
struct Feeder {
    queued: Vec<u8>,
    reads: usize,
    /// Cap on what a single read hands back; 0 means "no cap".
    drip: usize,
}

impl Feeder {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            queued: bytes,
            reads: 0,
            drip: 0,
        }
    }

    fn dripping(bytes: Vec<u8>, drip: usize) -> Self {
        Self {
            queued: bytes,
            reads: 0,
            drip,
        }
    }
}

impl embedded_io::ErrorType for Feeder {
    type Error = MockErr;
}

impl Read for Feeder {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockErr> {
        self.reads += 1;
        let cap = if self.drip == 0 { buf.len() } else { self.drip };
        let n = self.queued.len().min(buf.len()).min(cap);
        buf[..n].copy_from_slice(&self.queued[..n]);
        self.queued.drain(..n);
        Ok(n)
    }
}

/// Never produces anything, so a read on it parks forever.
struct Parked;

impl embedded_io::ErrorType for Parked {
    type Error = MockErr;
}

impl Read for Parked {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, MockErr> {
        core::future::pending().await
    }
}

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("mock transports never park"),
    }
}

fn wire_packet(payload_len: usize) -> Vec<u8> {
    let payload = std::vec![0xAB; payload_len];
    let pkt = Packet::new(Command::Write, 1, 2, payload);
    let mut buf = BytesMut::new();
    pkt.encode(&mut buf, Checksum::Compute).unwrap();
    buf.to_vec()
}

/// Records the size of every `write` it is handed.
#[derive(Default)]
struct WriteLog {
    writes: Vec<usize>,
}

impl embedded_io::ErrorType for WriteLog {
    type Error = MockErr;
}

impl Write for WriteLog {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MockErr> {
        self.writes.push(buf.len());
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), MockErr> {
        Ok(())
    }
}

#[test]
fn a_large_packet_is_zeroed_once_however_it_arrives() {
    // Over TLS a read brings one 16 KiB record. The packet is staged,
    // and so zeroed, once however many reads fill it; staging afresh
    // for each would memset some 33 MiB for one 1 MiB WRTE. The slack
    // is the MIN_READ that the first, header-sized read is padded to.
    let wire = wire_packet(1 << 20);
    let mut t = Feeder::dripping(wire.clone(), 16 * 1024);
    let mut buf = BytesMut::new();
    ZEROED.with(|zeroed| zeroed.set(0));

    let pkt = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();

    assert_eq!(pkt.data.len(), 1 << 20);
    let zeroed = ZEROED.with(|zeroed| zeroed.get());
    assert!(
        zeroed <= wire.len() + MIN_READ,
        "zeroed {zeroed} bytes for a {}-byte packet",
        wire.len()
    );
}

#[test]
fn a_packet_is_written_as_header_then_payload() {
    // adbd reads the 24-byte header with an exact-size read, so on
    // USB a single transfer carrying header + payload overflows its
    // endpoint and drops the device off the bus.
    let mut t = WriteLog::default();
    let pkt = Packet::new(Command::Connect, 1, 2, &b"host::features=shell_v2\0"[..]);

    block_on(send_pkt(
        &mut t,
        &DesyncFlag::new(),
        &pkt,
        Checksum::Compute,
    ))
    .unwrap();

    assert_eq!(
        t.writes,
        std::vec![MESSAGE_SIZE, 24],
        "header and payload must go out as separate writes",
    );
}

#[test]
fn an_empty_packet_is_a_single_header_write() {
    let mut t = WriteLog::default();
    let pkt = Packet::close(ChannelIds {
        local: 1.into(),
        remote: 2.into(),
    });

    block_on(send_pkt(
        &mut t,
        &DesyncFlag::new(),
        &pkt,
        Checksum::Compute,
    ))
    .unwrap();

    assert_eq!(t.writes, std::vec![MESSAGE_SIZE]);
}

#[test]
fn future_does_not_carry_a_scratch_buffer() {
    let mut t = Feeder::new(Vec::new());
    let mut buf = BytesMut::new();
    let fut = recv_pkt(&mut t, &mut buf, MAX_PAYLOAD);
    let size = core::mem::size_of_val(&fut);
    assert!(
        size < 512,
        "recv_pkt future is {size} B — a scratch array that big lands in \
         every caller's future, which is what embedded tasks pay for",
    );
}

#[test]
fn a_large_packet_does_not_take_one_read_per_scratch_worth() {
    let wire = wire_packet(64 * 1024);
    let mut t = Feeder::new(wire.clone());
    let mut buf = BytesMut::new();

    let pkt = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();

    assert_eq!(pkt.data.len(), 64 * 1024);
    assert!(
        t.reads <= 4,
        "took {} reads for one packet: the payload length is known from \
         the header, so it should be requested in one go",
        t.reads,
    );
}

#[test]
fn a_cancelled_read_leaves_no_scratch_bytes_behind() {
    let mut t = Parked;
    let mut buf = BytesMut::from(&b"\x57\x52\x54\x45"[..]);
    let before = buf.clone();

    {
        let mut fut = pin!(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
    }

    assert_eq!(
        buf, before,
        "a dropped read must not leave placeholder bytes in the buffer",
    );
}

#[test]
fn a_packet_split_across_reads_is_reassembled() {
    // 7 bytes at a time, so the header itself spans four reads.
    let mut t = Feeder::dripping(wire_packet(100), 7);
    let mut buf = BytesMut::new();

    let pkt = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();

    assert_eq!(pkt.data.len(), 100);
    assert_eq!(&pkt.data[..], &[0xAB; 100][..]);
    assert!(buf.is_empty(), "nothing should be left over");
}

#[test]
fn bytes_beyond_the_packet_stay_buffered() {
    let mut wire = wire_packet(8);
    let trailing = wire_packet(4);
    wire.extend_from_slice(&trailing);

    let mut t = Feeder::new(wire);
    let mut buf = BytesMut::new();

    let first = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();
    assert_eq!(first.data.len(), 8);

    let second = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();
    assert_eq!(second.data.len(), 4, "the second packet must survive");
}
