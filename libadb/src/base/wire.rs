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

pub(crate) const MIN_READ: usize = 4096;

#[cfg(test)]
pub(crate) use tests::ZEROED;

fn read_limit(buf: &[u8]) -> usize {
    if buf.len() < MESSAGE_SIZE {
        MIN_READ
    } else {
        Packet::missing(buf)
    }
}

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

    pub(crate) fn room(&mut self) -> &mut [u8] {
        let limit = read_limit(self.committed());
        let spare = self.spare();
        let room = limit.min(spare.len());
        &mut spare[..room]
    }

    pub(crate) fn commit(&mut self, n: usize) {
        self.keep += n;
    }

    pub(crate) fn committed(&self) -> &[u8] {
        &self.buf[..self.keep]
    }

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

pub(crate) fn connection_gone<E: embedded_io::Error>(e: &Error<E>) -> bool {
    use embedded_io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};
    matches!(e, Error::Io(e) if matches!(
        e.kind(),
        ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected
    ))
}

#[cfg(feature = "split")]
pub(crate) fn ends_connection<E: embedded_io::Error>(e: &Error<E>) -> bool {
    match e {
        Error::UnexpectedEof => true,
        Error::Protocol(e) => *e != ProtocolError::InvalidChecksum,
        e => connection_gone(e),
    }
}

pub(crate) struct DesyncFlag(AtomicBool);

impl DesyncFlag {
    pub(crate) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

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

pub(crate) enum Received<I> {
    Packet(Packet),
    Interrupted(I),
}

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
    t.flush().await.map_err(Error::Io)
}

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
