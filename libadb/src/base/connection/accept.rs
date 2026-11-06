use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::Connection;
use crate::base::channel::ChannelId;
use crate::base::incoming::PendingOpen;
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::wire::{connection_gone, send_pkt};
use crate::error::Error;

/// A device-initiated channel awaiting a verdict.
///
/// Borrow of the connection: decide with [`accept`](Self::accept) or
/// [`reject`](Self::reject). Dropping it undecided puts the request
/// back at the head of the queue.
pub struct Incoming<'c, T>
where
    T: Read + Write,
{
    pub(super) conn: &'c mut Connection<T>,
    pub(super) pending: Option<PendingOpen>,
    pub(super) reserved: Option<ChannelId>,
}

impl<T> Incoming<'_, T>
where
    T: Read + Write,
{
    /// The destination the device asked for, e.g. `tcp:8080\0`.
    pub fn destination(&self) -> &[u8] {
        &self.pending.as_ref().expect("undecided").destination
    }

    /// Take the channel: allocates a slot, answers READY (carrying our
    /// receive credit when delayed ack is on) and returns the channel,
    /// ready for [`read_channel`](Connection::read_channel) and
    /// [`write_channel`](Connection::write_channel).
    ///
    /// With every slot in use the request is refused with CLSE and
    /// [`Error::NoFreeChannels`] comes back.
    ///
    /// A READY or CLSE that fails comes back as the error, with the slot
    /// released and the request back in the queue. If the device is gone
    /// the request is consumed instead, and the next
    /// [`accept_incoming`](Connection::accept_incoming) goes on to
    /// whatever comes after it.
    ///
    /// Dropping this future never loses the request: the reserved slot
    /// is released and the request returns to the queue. A drop after
    /// the READY's write was first polled still desynchronizes the
    /// connection: see [`Error::Desynchronized`].
    pub async fn accept(mut self) -> Result<ChannelId, Error<<T as ErrorType>::Error>> {
        let pending = self.pending.as_ref().expect("undecided");
        let (remote, credit) = (pending.remote, pending.credit);

        let Ok(ch) = self.conn.table.allocate() else {
            self.answer(&Packet::refuse(remote)).await?;
            return Err(Error::NoFreeChannels);
        };
        self.conn.table.insert_accepted(ch, remote, credit);
        self.reserved = Some(ch);

        let payload = match self.conn.negotiated.advertised_credit() {
            Some(credit) => credit.to_le_bytes().to_vec(),
            None => alloc::vec::Vec::new(),
        };
        self.answer(&Packet::new(
            Command::Ready,
            ch.local.raw(),
            remote.raw(),
            payload,
        ))
        .await?;

        self.reserved = None;
        Ok(ch)
    }

    /// Refuse the channel: answers CLSE and frees nothing, since
    /// nothing was allocated.
    ///
    /// A CLSE that fails comes back as the error, with the request back
    /// in the queue. If the device is gone the request is consumed
    /// instead, and the next
    /// [`accept_incoming`](Connection::accept_incoming) goes on to
    /// whatever comes after it.
    ///
    /// Dropping this future never loses the request: it returns to the
    /// queue. A drop after the CLSE's write was first polled still
    /// desynchronizes the connection: see [`Error::Desynchronized`].
    pub async fn reject(mut self) -> Result<(), Error<<T as ErrorType>::Error>> {
        let remote = self.pending.as_ref().expect("undecided").remote;
        self.answer(&Packet::refuse(remote)).await
    }

    async fn answer(&mut self, verdict: &Packet) -> Result<(), Error<<T as ErrorType>::Error>> {
        let checksum = self.conn.negotiated.checksum();
        let sent = send_pkt(
            &mut self.conn.transport,
            &self.conn.desync,
            verdict,
            checksum,
        )
        .await;
        if sent.as_ref().err().is_none_or(connection_gone) {
            self.pending.take();
        }
        sent
    }
}

impl<T> Drop for Incoming<'_, T>
where
    T: Read + Write,
{
    fn drop(&mut self) {
        if let Some(ch) = self.reserved.take() {
            self.conn.table.free(ch);
        }
        if let Some(pending) = self.pending.take() {
            self.conn.incoming.push_front(pending);
        }
    }
}
