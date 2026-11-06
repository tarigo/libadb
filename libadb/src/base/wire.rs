#[cfg(test)]
mod tests;

use core::convert::Infallible;
use core::future::{pending, poll_fn, Future};
use core::pin::{pin, Pin};
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;

use bytes::BytesMut;
use embedded_io_async::{Read, Write};

use super::ids::{ChannelIds, LocalId};
use super::negotiated::AckMode;
use super::protocol::command::Command;
use super::protocol::constant::MAX_PAYLOAD;
use super::protocol::Packet;
use super::protocol::{Checksum, MESSAGE_SIZE};
use super::slot::PendingAck;
use crate::error::{Error, ProtocolError};

/// What a read asks for while the next header is incomplete, rather
/// than the few bytes that header lacks: a stream transport hands over
/// a whole packet, or several, in one go. USB loses nothing by it, as a
/// header is a transfer of its own there and its short packet ends the
/// read. Once the header is in, [`read_limit`] holds a read to the
/// packet.
pub(crate) const MIN_READ: usize = 4096;

#[cfg(test)]
pub(crate) use tests::ZEROED;

/// How much the next read may ask for when `buf` starts with an
/// unfinished packet: [`MIN_READ`] until the header is in, and from then
/// on what the packet still lacks.
///
/// USB is why a read stops at the packet. A bulk IN transfer ends at a
/// short packet or when the request is full, and adbd sends no
/// zero-length packet, so a request that reaches past a payload filling
/// its last USB packet stays open until the device next sends something.
fn read_limit(buf: &[u8]) -> usize {
    if buf.len() < MESSAGE_SIZE {
        MIN_READ
    } else {
        Packet::missing(buf)
    }
}

/// Grows `buf` by its [`read_limit`] and hands out that tail to be read
/// into, cutting the buffer back to whatever was committed when dropped
/// — so a failed or cancelled read leaves no placeholder bytes behind.
pub(crate) struct Staged<'a> {
    buf: &'a mut BytesMut,
    keep: usize,
}

impl<'a> Staged<'a> {
    pub(crate) fn new(buf: &'a mut BytesMut) -> Self {
        let keep = buf.len();
        let want = read_limit(buf);
        buf.resize(keep + want, 0);
        #[cfg(test)]
        tests::ZEROED.with(|zeroed| zeroed.set(zeroed.get() + want));
        Self { buf, keep }
    }

    fn spare(&mut self) -> &mut [u8] {
        &mut self.buf[self.keep..]
    }

    /// What the next read gets to fill: the stretch that is left, up to
    /// [`read_limit`]. What was staged for a header can run past the
    /// packet that header announces.
    pub(crate) fn room(&mut self) -> &mut [u8] {
        let limit = read_limit(self.committed());
        let spare = self.spare();
        let room = limit.min(spare.len());
        &mut spare[..room]
    }

    pub(crate) fn commit(&mut self, n: usize) {
        self.keep += n;
    }

    /// Everything committed so far: what was there before, and what has
    /// been read in since.
    pub(crate) fn committed(&self) -> &[u8] {
        &self.buf[..self.keep]
    }

    /// Whether to read into the same stretch again: the first packet is
    /// still short, and all it lacks fits in what is left. Staging anew
    /// for each read would zero the rest of a large packet every time,
    /// and over TLS a read brings only one 16 KiB record. The next read
    /// takes [`room`](Self::room), which may be less than is left.
    pub(crate) fn wants_more(&mut self) -> bool {
        let missing = Packet::missing(self.committed());
        missing != 0 && missing <= self.spare().len()
    }
}

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        self.buf.truncate(self.keep);
    }
}

/// Whether `e` says for certain that the other end is gone: nothing
/// more can be sent to it, whereas what it sent before going can still
/// be read.
///
/// A timeout is no such thing, and cannot be told from it by anything
/// short of these kinds: on unix `SO_RCVTIMEO` comes back as
/// `WouldBlock`, which `embedded_io` has no kind for but
/// [`Other`](embedded_io::ErrorKind::Other).
pub(crate) fn connection_gone<E: embedded_io::Error>(e: &Error<E>) -> bool {
    use embedded_io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};
    matches!(e, Error::Io(e) if matches!(
        e.kind(),
        ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected
    ))
}

/// Whether a failed receive means nothing more will come in, which is
/// to say what is certain: the stream ended, the transport says the
/// other end is gone, or what came in does not parse, which leaves the
/// bytes in place for every later read to fail on.
///
/// Everything else stays recoverable, a read timeout above all. So does
/// a wrong checksum, the one failure of a packet that has been taken off
/// the stream, which still has its place.
#[cfg(feature = "split")]
pub(crate) fn ends_connection<E: embedded_io::Error>(e: &Error<E>) -> bool {
    match e {
        Error::UnexpectedEof => true,
        Error::Protocol(e) => *e != ProtocolError::InvalidChecksum,
        e => connection_gone(e),
    }
}

/// Tracks whether a packet was left half-written.
///
/// A packet goes out as a header write followed by a payload write. Drop
/// the future in between — a cancelled `write_channel`, a `select!` that
/// lost the race — and the device is left waiting for a payload it will
/// take from whatever we send next. Nothing on this side can put the
/// framing back, so the flag is one-way: once raised, every operation on
/// the connection fails with [`Error::Desynchronized`], reads once they
/// have handed over what had already arrived.
pub(crate) struct DesyncFlag(AtomicBool);

impl DesyncFlag {
    pub(crate) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Fail if a packet was already abandoned mid-write.
    pub(crate) fn check<E>(&self) -> Result<(), Error<E>> {
        if self.0.load(Ordering::Acquire) {
            return Err(Error::Desynchronized);
        }
        Ok(())
    }

    fn arm(&self) -> ArmedWrite<'_> {
        ArmedWrite(Some(self))
    }
}

/// Raises its flag if dropped before the packet is fully written.
struct ArmedWrite<'a>(Option<&'a DesyncFlag>);

impl ArmedWrite<'_> {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for ArmedWrite<'_> {
    fn drop(&mut self) {
        if let Some(flag) = self.0 {
            flag.0.store(true, Ordering::Release);
        }
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
    desync: &DesyncFlag,
    pkt: &Packet,
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    desync.check()?;
    let header = encode_header(pkt.command, pkt.arg0, pkt.arg1, &pkt.data, checksum)?;
    send_frame(t, desync, &header, &pkt.data).await
}

/// Rejects any packet whose announced payload exceeds `max_payload`.
pub(crate) async fn recv_pkt<T: Read>(
    t: &mut T,
    buf: &mut BytesMut,
    max_payload: u32,
) -> Result<Packet, Error<T::Error>> {
    match recv_pkt_or(t, buf, max_payload, pin!(pending::<Infallible>()), true).await? {
        Received::Packet(pkt) => Ok(pkt),
        Received::Interrupted(never) => match never {},
    }
}

/// What [`recv_pkt_or`] came back with.
pub(crate) enum Received<I> {
    Packet(Packet),
    Interrupted(I),
}

/// [`recv_pkt`], giving up once `interrupt` resolves while the packet
/// still has to be read.
///
/// A packet already whole in `buf` wins over a ready interrupt. With
/// `race`, every read is raced against `interrupt` and dropped when it
/// loses, which only a transport whose reads are cancel-safe can
/// afford. Without it, `interrupt` is asked once before each read, and
/// a read once issued runs to completion. Bytes read before the
/// interrupt stay in `buf` either way.
///
/// Every read keeps to [`read_limit`], so USB gets requests it can
/// complete. TCP keeps its header reads, which take in a whole packet
/// or several; all it gives up is the read that finishes a split packet
/// bringing the next one along. TLS keeps its stretch: a large packet
/// is staged once, however many records fill it.
pub(crate) async fn recv_pkt_or<T: Read, F: Future>(
    t: &mut T,
    buf: &mut BytesMut,
    max_payload: u32,
    mut interrupt: Pin<&mut F>,
    race: bool,
) -> Result<Received<F::Output>, Error<T::Error>> {
    loop {
        if let Some(pkt) = Packet::decode(buf, max_payload)? {
            return Ok(Received::Packet(pkt));
        }
        let mut staged = Staged::new(buf);
        loop {
            let got = if race {
                let mut read = pin!(t.read(staged.room()));
                let raced = poll_fn(|cx| {
                    if let Poll::Ready(val) = interrupt.as_mut().poll(cx) {
                        return Poll::Ready(Err(val));
                    }
                    read.as_mut().poll(cx).map(Ok)
                })
                .await;
                match raced {
                    Ok(got) => got,
                    Err(val) => return Ok(Received::Interrupted(val)),
                }
            } else {
                if let Poll::Ready(val) =
                    poll_fn(|cx| Poll::Ready(interrupt.as_mut().poll(cx))).await
                {
                    return Ok(Received::Interrupted(val));
                }
                t.read(staged.room()).await
            };
            match got {
                Ok(0) => return Err(Error::UnexpectedEof),
                Ok(n) => staged.commit(n),
                Err(e) => return Err(Error::Io(e)),
            }
            if !staged.wants_more() {
                break;
            }
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

/// [`send_pkt`] for a packet on the channel `ids` names, its payload
/// borrowed rather than built into a [`Packet`].
pub(crate) async fn send_raw<T: Write>(
    t: &mut T,
    desync: &DesyncFlag,
    command: Command,
    ids: ChannelIds,
    payload: &[u8],
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    desync.check()?;
    let header = encode_header(
        command,
        ids.local.raw(),
        ids.remote.raw(),
        payload,
        checksum,
    )?;
    send_frame(t, desync, &header, payload).await
}

/// [`send_pkt`] for OPEN from our end `local` to `destination`, which
/// is borrowed rather than copied into a [`Packet`]. `credit` is the
/// receive credit `arg1` advertises: zero without delayed ACK.
pub(crate) async fn send_open<T: Write>(
    t: &mut T,
    desync: &DesyncFlag,
    local: LocalId,
    credit: u32,
    destination: &[u8],
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    desync.check()?;
    let header = encode_header(Command::Open, local.raw(), credit, destination, checksum)?;
    send_frame(t, desync, &header, destination).await
}

/// Put an encoded header and its payload on the wire, raising `desync`
/// if the packet does not get out whole.
///
/// Unless the other end is gone. Then no stream is left to fall out of
/// step with, and raising the flag would only stop reads short of what
/// it sent before it went.
async fn send_frame<T: Write>(
    t: &mut T,
    desync: &DesyncFlag,
    header: &[u8; MESSAGE_SIZE],
    payload: &[u8],
) -> Result<(), Error<T::Error>> {
    let armed = desync.arm();
    let sent = write_frame(t, header, payload).await;
    if sent.as_ref().err().is_none_or(connection_gone) {
        armed.disarm();
    }
    sent
}

async fn write_frame<T: Write>(
    t: &mut T,
    header: &[u8; MESSAGE_SIZE],
    payload: &[u8],
) -> Result<(), Error<T::Error>> {
    write_all(t, header).await?;
    if !payload.is_empty() {
        write_all(t, payload).await?;
    }
    // A transport that buffers, as TLS does, may still hold part of the
    // packet, and only the flush puts all of it on the wire; the rest
    // have nothing to flush. So it stays inside the armed stretch.
    t.flush().await.map_err(Error::Io)
}

/// Send the OKAY `ack` stands for. Under delayed ACK it carries the
/// bytes acknowledged, as credit; the classic OKAY carries nothing.
pub(crate) async fn send_okay_to<T: Write>(
    transport: &mut T,
    desync: &DesyncFlag,
    ack: PendingAck,
    mode: AckMode,
    checksum: Checksum,
) -> Result<(), Error<T::Error>> {
    let credit = (ack.len as u32).to_le_bytes();
    let payload: &[u8] = match mode {
        AckMode::Delayed => &credit,
        AckMode::Classic => &[],
    };
    send_raw(
        transport,
        desync,
        Command::Ready,
        ack.ids,
        payload,
        checksum,
    )
    .await
}
