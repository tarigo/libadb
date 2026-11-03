//! What the [`Reader`] and every [`Writer`] of one connection share,
//! and the guards that tidy up after a call dropped halfway.

use alloc::sync::Arc;
use async_lock::Mutex as AsyncMutex;
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use embedded_io::ErrorType;
use embedded_io_async::Write;
use event_listener::{Event, EventListener};
use std::sync::Mutex;

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::SplitIncoming;
use crate::base::channel::{ChannelFault, ChannelId, PendingAck};
use crate::base::channel_table::ChannelTable;
use crate::base::error::Error;
use crate::base::ids::{ChannelIds, RemoteId};
use crate::base::incoming::{IncomingQueue, PendingOpen};
use crate::base::negotiated::Negotiated;
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::wire::{send_okay_to, send_pkt, DesyncFlag};

#[cfg(doc)]
use super::{IncomingListener, Reader, Writer};

pub(super) struct FlowSignal {
    event: Event,
}

impl FlowSignal {
    const fn new() -> Self {
        Self {
            event: Event::new(),
        }
    }

    pub(super) fn listen(&self) -> EventListener {
        self.event.listen()
    }

    /// Wake every writer parked on this channel.
    ///
    /// Waking is only a prompt to look again: admission is decided by
    /// the slot's send queue, so writers that are not at its head check
    /// their place and park right back. That keeps credit impossible to
    /// lose to a missed or stolen notification — order lives in data
    /// under the channels mutex, not in wake delivery.
    pub(super) fn wake(&self) {
        self.event.notify(usize::MAX);
    }
}

/// What the [`Reader`] and every [`Writer`] of one connection share.
pub(crate) struct Shared<WH> {
    pub(super) write_half: AsyncMutex<WH>,
    channels: Mutex<ChannelTable>,
    /// One per slot of `channels`.
    pub(super) signals: Box<[FlowSignal]>,
    pub(super) negotiated: Negotiated,
    pub(super) desync: DesyncFlag,
    /// Device-initiated OPENs awaiting [`Reader::accept_incoming`].
    incoming: Mutex<IncomingQueue>,
    /// Requests staged out of the queue in an owned [`SplitIncoming`],
    /// by remote id — the only place a device cancellation can still
    /// reach them once they have left `incoming`.
    staged: Mutex<Vec<(RemoteId, Arc<AtomicBool>)>>,
    /// Set once the [`Reader`] is gone: nothing will dispatch packets
    /// any more, so waiting for one would never end.
    stopped: AtomicBool,
    /// Live [`IncomingListener`]s. While there is one, [`Reader::run`]
    /// keeps device-initiated OPENs for it instead of refusing them.
    pub(super) listeners: AtomicUsize,
    /// Woken when an OPEN is queued, for [`IncomingListener::accept`].
    pub(super) incoming_signal: Event,
    /// CLSEs for channels the device accepted just as their opener gave
    /// up: `Drop` cannot send them, so whoever takes the write half
    /// next does.
    owed_closes: Mutex<Vec<ChannelIds>>,
}

impl<WH> Shared<WH> {
    /// The shared half of a connection being split: its write half,
    /// what its handshake settled, its channels and the OPENs still
    /// waiting for a verdict, and whether it already lost step.
    pub(crate) fn new(
        write_half: WH,
        negotiated: Negotiated,
        table: ChannelTable,
        incoming: IncomingQueue,
        desync: DesyncFlag,
    ) -> Self {
        Self {
            write_half: AsyncMutex::new(write_half),
            signals: (0..table.len()).map(|_| FlowSignal::new()).collect(),
            channels: Mutex::new(table),
            negotiated,
            desync,
            incoming: Mutex::new(incoming),
            staged: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
            listeners: AtomicUsize::new(0),
            incoming_signal: Event::new(),
            owed_closes: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn lock_channels(&self) -> std::sync::MutexGuard<'_, ChannelTable> {
        self.channels.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn lock_incoming(&self) -> std::sync::MutexGuard<'_, IncomingQueue> {
        self.incoming.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn lock_staged(
        &self,
    ) -> std::sync::MutexGuard<'_, Vec<(RemoteId, Arc<AtomicBool>)>> {
        self.staged.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn lock_owed(&self) -> std::sync::MutexGuard<'_, Vec<ChannelIds>> {
        self.owed_closes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve a free slot and send OPEN for `destination` — the start
    /// both openers share. The guard frees the slot unless the opener
    /// disarms it once the device answers.
    pub(super) async fn send_open(
        self: &Arc<Self>,
        destination: &[u8],
    ) -> Result<(ChannelId, SlotGuard<WH>), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let ch = {
            let mut chs = self.lock_channels();
            let ch = chs.allocate()?;
            chs.insert_opening(ch);
            ch
        };
        let guard = SlotGuard::new(Arc::clone(self), ch);

        let open_arg1 = self.negotiated.advertised_credit().unwrap_or(0);
        let pkt = Packet::new(
            Command::Open,
            ch.local.raw(),
            open_arg1,
            destination.to_vec(),
        );
        {
            let mut wh = self.lock_write().await?;
            send_pkt(&mut *wh, &self.desync, &pkt, self.negotiated.checksum()).await?;
        }
        Ok((ch, guard))
    }

    /// Close a channel a packet broke on its own: its calls fail with
    /// `fault` from now on, and the device gets its CLSE. The CLSE goes
    /// out even when the slot is gone by now — an opener given up on in
    /// the meantime took it, and the device still holds its end; a
    /// second CLSE for a channel already closed is one adbd ignores.
    pub(super) async fn fail_channel(
        &self,
        idx: usize,
        ids: ChannelIds,
        fault: ChannelFault,
    ) -> Result<(), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let found = {
            let mut chs = self.lock_channels();
            let ch = ChannelId {
                slot: idx,
                local: ids.local,
            };
            chs.get_mut(ch).map(|s| s.fail(fault)).is_some()
        };
        if found {
            self.signals[idx].wake();
        }
        let mut wh = self.lock_write().await?;
        send_pkt(
            &mut *wh,
            &self.desync,
            &Packet::close(ids),
            self.negotiated.checksum(),
        )
        .await
    }

    /// Take what `ch` has buffered into `buf` and send the OKAY it
    /// owes: `Ok(None)` while an open channel has nothing buffered.
    ///
    /// Bytes that owe an acknowledgement leave the buffer only once the
    /// write lock is held to send it, so a call dropped while it waits
    /// for that lock has taken nothing.
    pub(super) async fn take_buffered(
        &self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<Option<usize>, Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        {
            let mut chs = self.lock_channels();
            let slot = chs.get_mut(ch).ok_or(Error::ChannelClosed)?;
            // Nothing to take, or nothing this take acknowledges: no
            // OKAY to send, so no lock to wait for.
            if !slot.take_acks(buf.len()) {
                let taken = slot.take_buffered(buf)?;
                return Ok(taken.map(|(n, _)| n));
            }
        }
        let mut wh = self.lock_write().await?;
        let taken = {
            let mut chs = self.lock_channels();
            let slot = chs.get_mut(ch).ok_or(Error::ChannelClosed)?;
            slot.take_buffered(buf)?
        };
        let Some((n, ack)) = taken else {
            return Ok(None);
        };
        if let Some(ack) = ack {
            send_okay_to(
                &mut *wh,
                &self.desync,
                ack,
                self.negotiated.ack_mode(),
                self.negotiated.checksum(),
            )
            .await?;
        }
        Ok(Some(n))
    }

    pub(super) async fn send_okay(
        &self,
        ack: PendingAck,
    ) -> Result<(), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let mut wh = self.lock_write().await?;
        send_okay_to(
            &mut *wh,
            &self.desync,
            ack,
            self.negotiated.ack_mode(),
            self.negotiated.checksum(),
        )
        .await
    }

    /// Wrap a request that never reached the queue in its owned
    /// holder, registering it so a device cancellation can still find
    /// it.
    pub(super) fn stage_incoming(self: &Arc<Self>, pending: PendingOpen) -> SplitIncoming<WH>
    where
        WH: Write,
    {
        self.hold_incoming(pending, &mut self.lock_staged())
    }

    /// Take the oldest queued device-initiated OPEN into its owned
    /// holder.
    pub(super) fn take_incoming(self: &Arc<Self>) -> Option<SplitIncoming<WH>>
    where
        WH: Write,
    {
        self.take_incoming_past(0)
    }

    /// [`take_incoming`](Self::take_incoming), but only while queued
    /// and staged requests together exceed `cap`.
    ///
    /// Popped and registered under the staged-then-incoming locks at
    /// once, the order `Drop` and the cancel dispatch take them: a
    /// device withdrawal racing this — `run` handles them while a
    /// listener accepts from another task — finds the request in one
    /// place or the other, never in between.
    pub(super) fn take_incoming_past(self: &Arc<Self>, cap: usize) -> Option<SplitIncoming<WH>>
    where
        WH: Write,
    {
        let mut staged = self.lock_staged();
        let mut incoming = self.lock_incoming();
        if staged.len() + incoming.len() <= cap {
            return None;
        }
        let pending = incoming.pop_front()?;
        Some(self.hold_incoming(pending, &mut staged))
    }

    fn hold_incoming(
        self: &Arc<Self>,
        pending: PendingOpen,
        staged: &mut Vec<(RemoteId, Arc<AtomicBool>)>,
    ) -> SplitIncoming<WH>
    where
        WH: Write,
    {
        let cancelled = Arc::new(AtomicBool::new(false));
        staged.push((pending.remote, Arc::clone(&cancelled)));
        SplitIncoming {
            shared: Arc::clone(self),
            pending: Some(pending),
            reserved: None,
            cancelled,
        }
    }

    /// Mark the connection unread and wake every waiter to see it.
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake_all();
    }

    fn wake_all(&self) {
        for signal in &self.signals {
            signal.wake();
        }
        self.incoming_signal.notify(usize::MAX);
    }

    /// Fail once waiting can no longer end well: a write abandoned
    /// mid-packet desynchronized the connection, or the [`Reader`] is
    /// gone and nothing will be dispatched any more.
    pub(super) fn check_live<E>(&self) -> Result<(), Error<E>> {
        self.desync.check()?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        Ok(())
    }

    /// Take the write half for one packet, once the owed CLSEs are out.
    pub(super) async fn lock_write(
        &self,
    ) -> Result<WriteLock<'_, WH>, Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let mut lock = WriteLock {
            guard: self.write_half.lock().await,
            shared: self,
        };
        loop {
            let owed = self.lock_owed().pop();
            let Some(ids) = owed else {
                return Ok(lock);
            };
            send_pkt(
                &mut *lock,
                &self.desync,
                &Packet::close(ids),
                self.negotiated.checksum(),
            )
            .await?;
        }
    }
}

/// The write half, held for one packet. A packet abandoned partway —
/// its future dropped, or the transport failing mid-write —
/// desynchronizes the connection, and letting go then wakes every
/// waiter to see that rather than wait for traffic that cannot come.
pub(super) struct WriteLock<'a, WH> {
    guard: async_lock::MutexGuard<'a, WH>,
    shared: &'a Shared<WH>,
}

impl<WH> core::ops::Deref for WriteLock<'_, WH> {
    type Target = WH;

    fn deref(&self) -> &WH {
        &self.guard
    }
}

impl<WH> core::ops::DerefMut for WriteLock<'_, WH> {
    fn deref_mut(&mut self) -> &mut WH {
        &mut self.guard
    }
}

impl<WH> Drop for WriteLock<'_, WH> {
    fn drop(&mut self) {
        if self.shared.desync.check::<Infallible>().is_err() {
            self.shared.wake_all();
        }
    }
}

pub(super) struct SlotGuard<WH> {
    shared: Arc<Shared<WH>>,
    ch: ChannelId,
    armed: bool,
}

impl<WH> SlotGuard<WH> {
    fn new(shared: Arc<Shared<WH>>, ch: ChannelId) -> Self {
        Self {
            shared,
            ch,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<WH> Drop for SlotGuard<WH> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut chs = self.shared.lock_channels();
        let Some(slot) = chs.free(self.ch) else {
            return;
        };
        // The device accepted before the opener gave up: its end is
        // open, and the CLSE for it is owed to whoever writes next.
        if let Some(ids) = slot.ids().filter(|_| !slot.is_failed()) {
            self.shared.lock_owed().push(ids);
        }
    }
}

pub(super) struct CreditGuard<'a, WH> {
    shared: &'a Shared<WH>,
    ch: ChannelId,
    n: usize,
    committed: bool,
}

impl<'a, WH> CreditGuard<'a, WH> {
    pub(super) fn new(shared: &'a Shared<WH>, ch: ChannelId, n: usize) -> Self {
        Self {
            shared,
            ch,
            n,
            committed: false,
        }
    }

    pub(super) fn commit(&mut self) {
        self.committed = true;
    }
}

impl<WH> Drop for CreditGuard<'_, WH> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        {
            let mut chs = self.shared.lock_channels();
            if let Some(slot) = chs.get_mut(self.ch) {
                slot.refund(self.n);
            }
        }
        if let Some(signal) = self.shared.signals.get(self.ch.slot) {
            signal.wake();
        }
    }
}

/// A place in a channel's send queue. Leaving without being served —
/// the write future was dropped mid-wait — gives the turn up, so the
/// queue keeps moving.
pub(super) struct QueueGuard<'a, WH> {
    pub(super) shared: &'a Shared<WH>,
    pub(super) ch: ChannelId,
    pub(super) place: u64,
    pub(super) served: bool,
}

impl<WH> Drop for QueueGuard<'_, WH> {
    fn drop(&mut self) {
        if self.served {
            return;
        }
        let head_moved = {
            let mut chs = self.shared.lock_channels();
            match chs.get_mut(self.ch) {
                Some(slot) => slot.send_queue().leave(self.place),
                None => false,
            }
        };
        if head_moved {
            if let Some(signal) = self.shared.signals.get(self.ch.slot) {
                signal.wake();
            }
        }
    }
}
