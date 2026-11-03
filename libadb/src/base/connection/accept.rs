//! [`Incoming`]: a channel the device opened, awaiting a verdict on a
//! connection that is not split.

use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::Connection;
use crate::base::channel::ChannelId;
use crate::base::incoming::PendingOpen;
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::wire::send_pkt;
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
    /// A slot reserved by `accept` before READY is on the wire. If the
    /// future is cancelled or errors before that, `Drop` frees it —
    /// otherwise a cancelled accept would occupy it forever.
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
    /// Dropping this future never loses the request: the reserved slot
    /// is released and the request returns to the queue. The connection
    /// itself survives only a drop that lands before the READY write is
    /// first polled — from that poll on, a drop abandons a packet
    /// mid-write and the connection is marked desynchronized, as with
    /// any cancelled write.
    pub async fn accept(mut self) -> Result<ChannelId, Error<<T as ErrorType>::Error>> {
        let pending = self.pending.as_ref().expect("undecided");
        let (remote, credit) = (pending.remote, pending.credit);
        let checksum = self.conn.negotiated.checksum();

        let Ok(ch) = self.conn.table.allocate() else {
            send_pkt(
                &mut self.conn.transport,
                &self.conn.desync,
                &Packet::refuse(remote),
                checksum,
            )
            .await?;
            self.pending.take();
            return Err(Error::NoFreeChannels);
        };
        self.conn.table.insert_accepted(ch, remote, credit);
        // Armed for rollback until READY is committed.
        self.reserved = Some(ch);

        let payload = match self.conn.negotiated.advertised_credit() {
            Some(credit) => credit.to_le_bytes().to_vec(),
            None => alloc::vec::Vec::new(),
        };
        send_pkt(
            &mut self.conn.transport,
            &self.conn.desync,
            &Packet::new(Command::Ready, ch.local.raw(), remote.raw(), payload),
            checksum,
        )
        .await?;

        // READY is out: the slot is committed and the request consumed.
        self.reserved = None;
        self.pending.take();
        Ok(ch)
    }

    /// Refuse the channel: answers CLSE and frees nothing, since
    /// nothing was allocated.
    ///
    /// Dropping this future never loses the request — it returns to the
    /// queue. The connection itself survives only a drop that lands
    /// before the CLSE write is first polled; after that it is marked
    /// desynchronized, as with any cancelled write.
    pub async fn reject(mut self) -> Result<(), Error<<T as ErrorType>::Error>> {
        let remote = self.pending.as_ref().expect("undecided").remote;
        let checksum = self.conn.negotiated.checksum();
        send_pkt(
            &mut self.conn.transport,
            &self.conn.desync,
            &Packet::refuse(remote),
            checksum,
        )
        .await?;
        self.pending.take();
        Ok(())
    }
}

impl<T> Drop for Incoming<'_, T>
where
    T: Read + Write,
{
    fn drop(&mut self) {
        // A slot reserved but never confirmed by READY: release it.
        if let Some(ch) = self.reserved.take() {
            self.conn.table.free(ch);
        }
        if let Some(pending) = self.pending.take() {
            self.conn.incoming.push_front(pending);
        }
    }
}
