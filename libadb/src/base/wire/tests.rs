extern crate std;

use super::*;
use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
use crate::base::mock::NoAuth;
use crate::base::protocol::command::{Command, ADB_VERSION};
use crate::base::protocol::Checksum;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
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

/// Records the size of every `write` it is handed, and the bytes of all
/// of them in order.
#[derive(Default)]
struct WriteLog {
    writes: Vec<usize>,
    bytes: Vec<u8>,
}

impl embedded_io::ErrorType for WriteLog {
    type Error = MockErr;
}

impl Write for WriteLog {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MockErr> {
        self.writes.push(buf.len());
        self.bytes.extend_from_slice(buf);
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
fn an_open_sent_from_its_borrowed_destination_is_the_packet_it_stands_for() {
    let mut t = WriteLog::default();
    let destination = b"shell:ls\0";

    block_on(send_open(
        &mut t,
        &DesyncFlag::new(),
        7.into(),
        4096,
        destination,
        Checksum::Compute,
    ))
    .unwrap();

    let mut expected = BytesMut::new();
    Packet::new(Command::Open, 7, 4096, &destination[..])
        .encode(&mut expected, Checksum::Compute)
        .unwrap();
    assert_eq!(t.bytes, expected[..]);
    assert_eq!(t.writes, std::vec![MESSAGE_SIZE, destination.len()]);
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

/// What a header read is padded for: a stream with several packets
/// ready hands them all over in one read.
#[test]
fn a_header_read_takes_in_all_a_stream_has_ready() {
    let mut wire = wire_packet(100);
    wire.extend_from_slice(&wire_packet(1000));
    wire.extend_from_slice(&wire_packet(2000));
    let mut t = Feeder::new(wire);
    let mut buf = BytesMut::new();

    for len in [100, 1000, 2000] {
        let pkt = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();
        assert_eq!(pkt.data.len(), len);
    }

    assert_eq!(t.reads, 1);
}

/// The one thing a stream gives up to a read that stops at the packet:
/// finishing a split packet no longer brings the next one along, which
/// then takes a read of its own.
#[test]
fn finishing_a_split_packet_costs_a_stream_one_read() {
    let mut wire = wire_packet(100);
    wire.extend_from_slice(&wire_packet(100));
    let mut t = Feeder::dripping(wire, 100);
    let mut buf = BytesMut::new();

    block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();
    assert_eq!(t.reads, 2);
    assert!(buf.is_empty(), "the read stops where the packet does");

    block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();
    assert_eq!(t.reads, 4);
}

/// A read resumed in mid-packet stages what the packet lacks, by the
/// rule the read itself goes by, rather than zero a stretch it will not
/// fill.
#[test]
fn the_rest_of_a_packet_is_staged_to_its_length() {
    let wire = wire_packet(100);
    let (held, rest) = wire.split_at(MESSAGE_SIZE + 40);
    let mut t = Feeder::new(rest.to_vec());
    let mut buf = BytesMut::from(held);
    ZEROED.with(|zeroed| zeroed.set(0));

    let pkt = block_on(recv_pkt(&mut t, &mut buf, MAX_PAYLOAD)).unwrap();

    assert_eq!(pkt.data.len(), 100);
    assert_eq!(ZEROED.with(|zeroed| zeroed.get()), rest.len());
}

/// The largest transfer `daemon/usb.cpp` writes; a longer payload is
/// split at this size.
const ADBD_WRITE_SIZE: usize = 16384;

/// Payload lengths around what could go wrong: the USB packet, what a
/// header read leaves of its stretch, and adbd's largest transfer.
const PAYLOADS: [usize; 15] = [
    0,
    1,
    511,
    512,
    513,
    1024,
    3584,
    4072,
    4073,
    4096,
    8192,
    ADBD_WRITE_SIZE,
    ADBD_WRITE_SIZE + 1,
    ADBD_WRITE_SIZE + 512,
    4 * ADBD_WRITE_SIZE,
];

/// A bulk IN endpoint, as the host sees it.
///
/// The device's transfers queue up, and a read takes them in the way a
/// USB request does: it completes when it is full, or at the short
/// packet that ends a transfer. A transfer that fills its last packet
/// leaves no mark on the wire, so a request with room left runs on into
/// the next transfer, and stays pending until there is one.
struct BulkIn {
    max_packet: usize,
    transfers: VecDeque<Vec<u8>>,
    /// How much of the front transfer earlier requests took.
    taken: usize,
    /// The length of every request, in order.
    requests: Vec<usize>,
}

impl BulkIn {
    fn new(max_packet: usize) -> Self {
        Self {
            max_packet,
            transfers: VecDeque::new(),
            taken: 0,
            requests: Vec::new(),
        }
    }

    fn transfer(&mut self, bytes: &[u8]) {
        self.transfers.push_back(bytes.to_vec());
    }

    /// Send `pkt` the way adbd does: the header in a transfer of its
    /// own, then the payload, split at [`ADBD_WRITE_SIZE`].
    fn send(&mut self, pkt: &Packet) {
        let mut wire = BytesMut::new();
        pkt.encode(&mut wire, Checksum::Compute).unwrap();
        let (header, payload) = wire.split_at(MESSAGE_SIZE);
        self.transfer(header);
        for transfer in payload.chunks(ADBD_WRITE_SIZE) {
            self.transfer(transfer);
        }
    }

    /// Take what has arrived into the request `buf`, whose first `got`
    /// bytes are in already, and report its length once it is over.
    fn fill(&mut self, buf: &mut [u8], got: &mut usize) -> Poll<usize> {
        while let Some(transfer) = self.transfers.front() {
            let n = (buf.len() - *got).min(transfer.len() - self.taken);
            buf[*got..][..n].copy_from_slice(&transfer[self.taken..][..n]);
            *got += n;
            self.taken += n;
            let finished = self.taken == transfer.len();
            let short = transfer.len() % self.max_packet != 0;
            if finished {
                self.transfers.pop_front();
                self.taken = 0;
            }
            if *got == buf.len() || (finished && short) {
                return Poll::Ready(*got);
            }
        }
        Poll::Pending
    }
}

impl embedded_io::ErrorType for BulkIn {
    type Error = MockErr;
}

impl Read for BulkIn {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockErr> {
        self.requests.push(buf.len());
        let mut got = 0;
        Ok(poll_fn(|_| self.fill(buf, &mut got)).await)
    }
}

/// The OUT side, for what a handshake sends: nothing listens to it.
impl Write for BulkIn {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, MockErr> {
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), MockErr> {
        Ok(())
    }
}

/// What `fut` comes to at its first poll, or `None` if it parks: on a
/// [`BulkIn`] that means waiting for a transfer that is not coming.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// The next packet, through `recv_pkt` with `race`, and without it the
/// way `select_channel` takes it over a transport whose reads are not
/// cancel-safe; `None` if it waits for a later transfer.
fn receive(t: &mut BulkIn, buf: &mut BytesMut, race: bool) -> Option<Packet> {
    if race {
        return poll_once(recv_pkt(t, buf, MAX_PAYLOAD)).map(Result::unwrap);
    }
    let interrupt = pin!(pending::<Infallible>());
    let received = poll_once(recv_pkt_or(t, buf, MAX_PAYLOAD, interrupt, false))?;
    match received.unwrap() {
        Received::Packet(pkt) => Some(pkt),
        Received::Interrupted(never) => match never {},
    }
}

/// What the tests below lean on: the transport hangs as real USB does.
#[test]
fn a_bulk_request_with_room_left_outlasts_a_transfer_that_fills_its_last_packet() {
    let mut t = BulkIn::new(512);
    t.transfer(&[1; 512]);
    let mut request = [0u8; 4072];
    let mut got = 0;
    assert_eq!(t.fill(&mut request, &mut got), Poll::Pending);

    t.transfer(&[2; 24]);
    assert_eq!(t.fill(&mut request, &mut got), Poll::Ready(536));

    t.transfer(&[3; 512]);
    let mut exact = [0u8; 512];
    assert_eq!(t.fill(&mut exact, &mut 0), Poll::Ready(512));
}

/// The defect itself: adbd ends no transfer that fills its last packet,
/// so a read for more than the packet would wait for whatever the
/// device sends next, which may be nothing at all.
#[test]
fn a_packet_over_bulk_in_completes_with_nothing_sent_after_it() {
    for max_packet in [64, 512, 1024] {
        for race in [true, false] {
            let mut t = BulkIn::new(max_packet);
            let mut buf = BytesMut::new();
            for len in PAYLOADS {
                let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let sent = Packet::new(Command::Write, 1, 2, payload);
                t.send(&sent);

                let got = receive(&mut t, &mut buf, race).unwrap_or_else(|| {
                    panic!("{len} bytes in {max_packet}-byte packets, race {race}: read hangs")
                });

                assert!(got == sent, "{len} bytes in {max_packet}-byte packets");
                assert!(buf.is_empty() && t.transfers.is_empty());
            }
        }
    }
}

/// Padding is for the header alone: from there on every request is what
/// the packet lacks, for any length that could leave one open.
#[test]
fn no_read_asks_past_the_packet_once_its_header_is_in() {
    for race in [true, false] {
        for len in PAYLOADS {
            let mut t = BulkIn::new(512);
            let mut buf = BytesMut::new();
            t.send(&Packet::new(Command::Write, 1, 2, std::vec![0xAB; len]));

            receive(&mut t, &mut buf, race).expect("the packet is all there");

            let due = &[MIN_READ, len][..if len == 0 { 1 } else { 2 }];
            assert_eq!(t.requests, due, "{len} bytes, race {race}");
        }
    }
}

/// A short packet can end a transfer in mid-payload. The request after
/// it goes by what is left, whether it reads into what the header read
/// staged or into a stretch of its own.
#[test]
fn a_payload_that_comes_in_pieces_is_asked_for_by_what_is_left() {
    for race in [true, false] {
        for len in [512, 8192] {
            let wire = wire_packet(len);
            let (header, payload) = wire.split_at(MESSAGE_SIZE);
            let (start, rest) = payload.split_at(100);
            let mut t = BulkIn::new(512);
            t.transfer(header);
            t.transfer(start);
            t.transfer(rest);
            let mut buf = BytesMut::new();

            let pkt = receive(&mut t, &mut buf, race).expect("the packet is all there");

            assert_eq!(pkt.data.len(), len);
            assert_eq!(t.requests, [MIN_READ, len, len - 100], "race {race}");
        }
    }
}

/// The handshake reads the device's CNXN like any other packet, and
/// nothing comes behind that CNXN until the host answers it.
#[test]
fn a_banner_that_fills_its_last_usb_packet_does_not_hang_connect() {
    for (max_packet, len) in [(64, 512), (512, 512), (512, 1024), (1024, 1024)] {
        let mut banner = b"device::ro.product.name=".to_vec();
        banner.resize(len, b'x');
        let mut t = BulkIn::new(max_packet);
        t.send(&Packet::new(
            Command::Connect,
            ADB_VERSION,
            MAX_PAYLOAD,
            banner.clone(),
        ));

        let conn = poll_once(Connection::connect(
            t,
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap_or_else(|| panic!("a {len}-byte banner in {max_packet}-byte packets hangs"))
        .unwrap();

        assert_eq!(conn.device_banner(), banner);
    }
}
