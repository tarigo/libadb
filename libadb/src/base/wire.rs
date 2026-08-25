use bytes::BytesMut;
use embedded_io_async::{Read, Write};

use super::error::{Error, ProtocolError};
use super::protocol::command::Command;
use super::protocol::constant::MAX_PAYLOAD;
use super::protocol::packet::Packet;
use super::protocol::{Checksum, MESSAGE_SIZE};

/// Floor on how much to ask the transport for. A request smaller than
/// this is padded up to it, so a header-sized read does not split a
/// packet that would have arrived in one go.
pub(crate) const MIN_READ: usize = 4096;

/// Grows `buf` by `want` bytes and hands out that tail to be read into,
/// cutting the buffer back to whatever was committed when dropped — so
/// a failed or cancelled read leaves no placeholder bytes behind.
pub(crate) struct Staged<'a> {
    buf: &'a mut BytesMut,
    keep: usize,
}

impl<'a> Staged<'a> {
    pub(crate) fn new(buf: &'a mut BytesMut, want: usize) -> Self {
        let keep = buf.len();
        buf.resize(keep + want, 0);
        Self { buf, keep }
    }

    pub(crate) fn spare(&mut self) -> &mut [u8] {
        &mut self.buf[self.keep..]
    }

    pub(crate) fn commit(&mut self, n: usize) {
        self.keep += n;
    }
}

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        self.buf.truncate(self.keep);
    }
}

pub(crate) async fn write_all<T: Write>(t: &mut T, buf: &[u8]) -> Result<(), Error<T::Error>> {
    let mut pos = 0;
    while pos < buf.len() {
        match t.write(&buf[pos..]).await {
            Ok(0) => return Err(Error::UnexpectedEof),
            Ok(n) => pos += n,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

/// Send a packet as a header write followed by a payload write.
///
/// The split is required, not cosmetic: adbd reads the 24-byte header
/// with an exact-size read, so on USB a single transfer carrying both
/// overflows its endpoint and knocks the device off the bus.
pub(crate) async fn send_pkt<T: Write>(
    t: &mut T,
    pkt: &Packet,
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    send_raw(t, pkt.command, pkt.arg0, pkt.arg1, &pkt.data, checksum).await
}

/// Rejects any packet whose announced payload exceeds `max_payload`.
pub(crate) async fn recv_pkt<T: Read>(
    t: &mut T,
    buf: &mut BytesMut,
    max_payload: u32,
) -> Result<Packet, Error<T::Error>> {
    loop {
        if let Some(pkt) = Packet::decode(buf, max_payload)? {
            return Ok(pkt);
        }
        let want = Packet::missing(buf).max(MIN_READ);
        let mut staged = Staged::new(buf, want);
        match t.read(staged.spare()).await {
            Ok(0) => return Err(Error::UnexpectedEof),
            Ok(n) => staged.commit(n),
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

fn encode_header(
    command: Command,
    arg0: u32,
    arg1: u32,
    payload: &[u8],
    checksum: Checksum,
) -> Result<[u8; MESSAGE_SIZE], ProtocolError> {
    if payload.len() > MAX_PAYLOAD as usize {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let cmd_u32: u32 = command.into();
    let data_length = payload.len() as u32;
    let data_check = checksum.of(payload);
    let magic = command.magic();
    let mut h = [0u8; MESSAGE_SIZE];
    h[0..4].copy_from_slice(&cmd_u32.to_le_bytes());
    h[4..8].copy_from_slice(&arg0.to_le_bytes());
    h[8..12].copy_from_slice(&arg1.to_le_bytes());
    h[12..16].copy_from_slice(&data_length.to_le_bytes());
    h[16..20].copy_from_slice(&data_check.to_le_bytes());
    h[20..24].copy_from_slice(&magic.to_le_bytes());
    Ok(h)
}

pub(crate) async fn send_raw<T: Write>(
    t: &mut T,
    command: Command,
    arg0: u32,
    arg1: u32,
    payload: &[u8],
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    let header = encode_header(command, arg0, arg1, payload, checksum)?;
    write_all(t, &header).await?;
    if !payload.is_empty() {
        write_all(t, payload).await?;
    }
    Ok(())
}

pub(crate) async fn send_okay_to<T: Write>(
    transport: &mut T,
    delayed_ack: bool,
    local_id: u32,
    remote_id: u32,
    wrte_len: usize,
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    let ack = (wrte_len as u32).to_le_bytes();
    let payload: &[u8] = if delayed_ack { &ack } else { &[] };
    send_raw(
        transport,
        Command::Ready,
        local_id,
        remote_id,
        payload,
        checksum,
    )
    .await
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Checksum;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use std::vec::Vec;

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
    fn a_packet_is_written_as_header_then_payload() {
        // adbd reads the 24-byte header with an exact-size read, so on
        // USB a single transfer carrying header + payload overflows its
        // endpoint and drops the device off the bus.
        let mut t = WriteLog::default();
        let pkt = Packet::new(Command::Connect, 1, 2, &b"host::features=shell_v2\0"[..]);

        block_on(send_pkt(&mut t, &pkt, Checksum::Compute)).unwrap();

        assert_eq!(
            t.writes,
            std::vec![MESSAGE_SIZE, 24],
            "header and payload must go out as separate writes",
        );
    }

    #[test]
    fn an_empty_packet_is_a_single_header_write() {
        let mut t = WriteLog::default();
        let pkt = Packet::close(1, 2);

        block_on(send_pkt(&mut t, &pkt, Checksum::Compute)).unwrap();

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
}
