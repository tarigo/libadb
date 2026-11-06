//! Channels the device opens: [`SplitIncoming`], one request awaiting a
//! verdict, and [`IncomingListener`], which waits for them while
//! [`Reader::run`] dispatches.

use alloc::sync::Arc;
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, Ordering};
use embedded_io::ErrorType;
use embedded_io_async::Write;
use event_listener::EventListener;

use alloc::vec::Vec;

use super::shared::Shared;
use crate::base::channel::ChannelId;
use crate::base::incoming::PendingOpen;
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::wire::{connection_gone, send_pkt};
use crate::error::Error;

#[cfg(doc)]
use super::{Reader, Writer};

/// A device-initiated channel awaiting a verdict, on a split
/// connection. Owns the request — holding it does not borrow the
/// [`Reader`]. Dropping it undecided puts the request back at the head
/// of the queue.
pub struct SplitIncoming<WH>
where
    WH: Write,
{
    pub(super) shared: Arc<Shared<WH>>,
    pub(super) pending: Option<PendingOpen>,
    /// A slot reserved by `accept` before READY is on the wire. If the
    /// future is cancelled or errors before that, `Drop` frees it —
    /// otherwise a cancelled accept would occupy it forever.
    pub(super) reserved: Option<ChannelId>,
    /// Set by the reader when the device withdraws this OPEN (a CLSE
    /// naming no local id) while the request is staged here.
    pub(super) cancelled: Arc<AtomicBool>,
}

impl<WH> SplitIncoming<WH>
where
    WH: Write,
{
    /// The destination the device asked for, e.g. `tcp:8080\0`.
    pub fn destination(&self) -> &[u8] {
        &self.pending.as_ref().expect("undecided").destination
    }

    /// Take the channel: allocates a slot, answers READY (carrying our
    /// receive credit when delayed ack is on) and returns the channel.
    ///
    /// With every slot in use the request is refused with CLSE and
    /// [`Error::NoFreeChannels`] comes back.
    ///
    /// A READY or CLSE that fails comes back as the error, with the slot
    /// released and the request back in the queue, unless the device is
    /// gone: nobody is left to answer then, so the request is consumed,
    /// and the next [`IncomingListener::accept`] or
    /// [`Reader::accept_incoming`] goes on to whatever comes after it.
    ///
    /// Dropping this future never loses the request: the reserved slot
    /// is released and the request returns to the queue. The connection
    /// itself survives only a drop that lands before the READY write is
    /// first polled — waiting for the shared write lock included; from
    /// that poll on, a drop abandons a packet mid-write and the
    /// connection is marked desynchronized, as with any cancelled
    /// write.
    ///
    /// A request the device has withdrawn in the meantime (a CLSE for
    /// its OPEN) is not taken: no READY is sent and
    /// [`Error::ChannelClosed`] comes back.
    pub async fn accept(mut self) -> Result<ChannelId, Error<<WH as ErrorType>::Error>> {
        let pending = self.pending.as_ref().expect("undecided");
        let (remote, credit) = (pending.remote, pending.credit);
        let shared = Arc::clone(&self.shared);

        let reserved = {
            let mut chs = shared.lock_channels();
            // Checked under the channels lock, where withdrawals are
            // classified and handled: the flag is either already set
            // here, or the withdrawal arrives after the slot below
            // exists and closes it like a remote CLSE — there is no
            // in-between where it finds neither.
            if self.cancelled.load(Ordering::Relaxed) {
                self.pending.take();
                return Err(Error::ChannelClosed);
            }
            chs.allocate().ok().inspect(|&ch| {
                chs.insert_accepted(ch, remote, credit);
            })
        };
        let Some(ch) = reserved else {
            // No slot to give: refuse, and consume the request.
            self.answer(&Packet::refuse(remote)).await?;
            return Err(Error::NoFreeChannels);
        };
        // Armed for rollback until READY is committed.
        self.reserved = Some(ch);

        let payload = match shared.negotiated.advertised_credit() {
            Some(credit) => credit.to_le_bytes().to_vec(),
            None => Vec::new(),
        };
        self.answer(&Packet::new(
            Command::Ready,
            ch.local.raw(),
            remote.raw(),
            payload,
        ))
        .await?;

        // READY is out: the slot is committed.
        self.reserved = None;
        Ok(ch)
    }

    /// Refuse the channel: answers CLSE and frees nothing, since
    /// nothing was allocated.
    ///
    /// Dropping this future never loses the request — it returns to the
    /// queue. The connection itself survives only a drop that lands
    /// before the CLSE write is first polled, waiting for the shared
    /// write lock included; after that it is marked desynchronized, as
    /// with any cancelled write.
    ///
    /// A CLSE that fails comes back as the error, and the request
    /// returns to the queue, unless the device is gone: nobody is left
    /// to refuse then, and the request is consumed.
    ///
    /// A request the device has withdrawn in the meantime is consumed
    /// silently: it no longer expects an answer.
    pub async fn reject(mut self) -> Result<(), Error<<WH as ErrorType>::Error>> {
        if self.cancelled.load(Ordering::Relaxed) {
            self.pending.take();
            return Ok(());
        }
        let remote = self.pending.as_ref().expect("undecided").remote;
        self.answer(&Packet::refuse(remote)).await
    }

    /// Send `verdict`, which settles the request, as does finding the
    /// device gone: nobody is left to answer. Any other failure leaves
    /// the request undecided, for `Drop` to put back.
    async fn answer(&mut self, verdict: &Packet) -> Result<(), Error<<WH as ErrorType>::Error>> {
        let mut wh = self.shared.lock_write_half().await;
        let sent = send_pkt(
            &mut *wh,
            &self.shared.desync,
            verdict,
            self.shared.negotiated.checksum(),
        )
        .await;
        if sent.as_ref().err().is_none_or(connection_gone) {
            self.pending.take();
        }
        sent
    }
}

impl<WH> Drop for SplitIncoming<WH>
where
    WH: Write,
{
    fn drop(&mut self) {
        // A slot reserved but never confirmed by READY: release it.
        if let Some(ch) = self.reserved.take() {
            self.shared.lock_channels().free(ch);
        }
        // Unregister and requeue under both locks at once, in the same
        // staged-then-incoming order `Shared::withdraw_open` takes: a
        // withdrawal must find the request in one collection or the
        // other, never in the gap between them.
        let mut staged = self.shared.lock_staged();
        let mut incoming = self.shared.lock_incoming();
        staged.retain(|(_, flag)| !Arc::ptr_eq(flag, &self.cancelled));
        if let Some(pending) = self.pending.take() {
            // A withdrawn request is dead; anything else goes back, to
            // a listener that may already be waiting for one.
            if !self.cancelled.load(Ordering::Relaxed) {
                incoming.push_front(pending);
                self.shared.incoming_signal.notify(usize::MAX);
            }
        }
    }
}

/// Channels the device opens toward the host, taken on a connection
/// whose [`Reader::run`] dispatches packets. Made by
/// [`Writer::listen_incoming`]; while any listener lives, `run` keeps
/// such requests for it — up to the channel table's size, past which
/// they are refused on arrival — and refuses them once none does.
pub struct IncomingListener<WH>
where
    WH: Write,
{
    pub(super) shared: Arc<Shared<WH>>,
}

impl<WH> IncomingListener<WH>
where
    WH: Write,
{
    /// Wait for a device-initiated channel and hand it over for a
    /// verdict, as [`Reader::accept_incoming`] does on a reader-driven
    /// connection. The accepted channel is then worked through the
    /// [`Writer`] like any other.
    ///
    /// Cancellation-safe: a request is only taken once it is returned.
    pub async fn accept(&self) -> Result<SplitIncoming<WH>, Error<<WH as ErrorType>::Error>> {
        let mut listener: Option<EventListener> = None;
        loop {
            // A request taken now could get no verdict out: it would only
            // go back to the queue.
            if self.shared.desync.check::<Infallible>().is_err() {
                self.shared.check_live()?;
            }
            if let Some(incoming) = self.shared.take_incoming() {
                return Ok(incoming);
            }
            self.shared.check_live()?;
            // Register, then look once more before waiting, as reads do.
            match listener.take() {
                Some(waiting) => waiting.await,
                None => listener = Some(self.shared.incoming_signal.listen()),
            }
        }
    }
}

impl<WH> Drop for IncomingListener<WH>
where
    WH: Write,
{
    fn drop(&mut self) {
        self.shared.listeners.fetch_sub(1, Ordering::AcqRel);
    }
}
