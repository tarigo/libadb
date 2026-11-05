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
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::SplitIncoming;
use crate::base::channel::ChannelId;
use crate::base::channel_table::ChannelTable;
use crate::base::ids::{ChannelIds, RemoteId};
use crate::base::incoming::{IncomingQueue, PendingOpen};
use crate::base::negotiated::Negotiated;
use crate::base::protocol::Packet;
use crate::base::slot::{ChannelFault, ChannelSlot, PendingAck};
use crate::base::wire::{connection_gone, send_okay_to, send_open, send_pkt, DesyncFlag};
use crate::error::Error;

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
    /// Device-initiated OPENs awaiting [`Reader::accept_incoming`] or
    /// [`IncomingListener::accept`], which take from the same queue.
    incoming: Mutex<IncomingQueue>,
    /// Requests staged out of the queue in an owned [`SplitIncoming`],
    /// by remote id — the only place a device cancellation can still
    /// reach them once they have left `incoming`.
    staged: Mutex<Vec<(RemoteId, Arc<AtomicBool>)>>,
    /// Set once the connection ended, in a receive that cannot be taken
    /// back or with the [`Reader`] gone: nothing will dispatch packets
    /// any more, so waiting for one would never end.
    stopped: AtomicBool,
    /// Live [`IncomingListener`]s. While there is one, [`Reader::run`]
    /// keeps device-initiated OPENs for it instead of refusing them.
    pub(super) listeners: AtomicUsize,
    /// Woken when an OPEN is queued, for [`IncomingListener::accept`].
    pub(super) incoming_signal: Event,
    /// Woken with everyone else and when something falls due, for a
    /// receive in flight.
    receive_signal: Event,
    /// What the device is owed, oldest first: see [`Owed`].
    ///
    /// Bounded by nothing being received until it is empty, so one
    /// packet at most adds to it at a time, on top of the openers given
    /// up on, which hold a slot each until they go: no more than
    /// [`max_channels`](crate::ConnectionConfig::max_channels) + 1.
    owed: Mutex<VecDeque<Owed>>,
}

/// A packet the device is owed, kept here from before any wait until it
/// is on the wire. Waiting for the write half is a cancellation point,
/// and `Drop` cannot send anything, so
/// [`lock_write`](Shared::lock_write) sends it for the next call that
/// writes, and a call that receives does so first, or as soon as it can
/// give up on a read in flight.
#[derive(Clone, Copy)]
pub(super) enum Owed {
    /// The OKAY for data that arrived.
    Okay(PendingAck),
    /// The CLSE for an end the device holds open: an OPEN given up on as
    /// it answered, or a channel broken by a fault.
    Close(ChannelIds),
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
            receive_signal: Event::new(),
            owed: Mutex::new(VecDeque::new()),
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

    pub(super) fn lock_owed(&self) -> std::sync::MutexGuard<'_, VecDeque<Owed>> {
        self.owed.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Note a packet the device is owed. The caller has awaited nothing
    /// yet, so from here no dropped future can lose it.
    pub(super) fn owe(&self, debt: Owed) {
        self.lock_owed().push_back(debt);
        self.receive_signal.notify(usize::MAX);
    }

    /// Send what is owed, if anything is.
    pub(super) async fn pay(&self) -> Result<(), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        if !self.lock_owed().is_empty() {
            drop(self.lock_write().await?);
        }
        Ok(())
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

        let credit = self.negotiated.advertised_credit().unwrap_or(0);
        {
            let mut wh = self.lock_write().await?;
            send_open(
                &mut *wh,
                &self.desync,
                ch.local,
                credit,
                destination,
                self.negotiated.checksum(),
            )
            .await?;
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
        self.owe(Owed::Close(ids));
        self.pay().await
    }

    /// Take what `ch` has buffered into `buf` and send the OKAY it
    /// owes: `Ok(None)` while an open channel has nothing buffered.
    ///
    /// What arrived is handed over whatever has become of the
    /// connection, and only once nothing is left does a read fail with
    /// that: a write given up on says nothing about bytes the device
    /// already delivered. Nor does a failed OKAY fail the read it
    /// belongs to. The failure is the connection's, and the next call
    /// reports it.
    ///
    /// Bytes that owe an acknowledgement leave the buffer only once it
    /// has been sent, so a call dropped while it waits for the write
    /// lock has taken nothing, and one dropped in the middle of the
    /// write leaves the bytes readable, with no gap in them.
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
            if !chs.get(ch).is_some_and(ChannelSlot::has_data) {
                self.desync.check()?;
            }
            let slot = chs.get_mut(ch).ok_or(Error::ChannelClosed)?;
            // Nothing to take, nothing this take acknowledges, or nobody
            // left to send it to: no OKAY, so no lock to wait for.
            if self.check_live::<Infallible>().is_err() || !slot.take_acks(buf.len()) {
                return slot.take_buffered(buf);
            }
        }
        let mut wh = self.lock_write_half().await;
        let ack = {
            let mut chs = self.lock_channels();
            let slot = chs.get_mut(ch).ok_or(Error::ChannelClosed)?;
            slot.settle_take(buf.len())
        };
        if let Some(ack) = ack {
            let _ = send_okay_to(
                &mut *wh,
                &self.desync,
                ack,
                self.negotiated.ack_mode(),
                self.negotiated.checksum(),
            )
            .await;
        }
        let mut chs = self.lock_channels();
        let slot = chs.get_mut(ch).ok_or(Error::ChannelClosed)?;
        slot.take_buffered(buf)
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
    /// once, the order `Drop` and [`withdraw_open`](Self::withdraw_open)
    /// take them: a device withdrawal racing this — `run` handles them
    /// while a listener accepts from another task — finds the request
    /// in one place or the other, never in between.
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

    /// Queue a device-initiated OPEN for a verdict, or refuse it once
    /// queued and staged requests together fill the channel table.
    ///
    /// Bounded by the channel table: past that, an OPEN storm is
    /// refused on arrival rather than remembered. Held holders spend the
    /// same budget as queued requests — otherwise an application sitting
    /// on holders would drain the queue and let payloads accumulate
    /// without limit.
    ///
    /// The refusal owes adbd a CLSE, and waiting for the write lock is a
    /// cancellation point: dropped there, the OPEN would vanish
    /// unanswered with the connection still healthy. So it goes to the
    /// verdict machinery instead — [`SplitIncoming::reject`] keeps the
    /// request recoverable until CLSE is committed, and the holder's
    /// `Drop` re-queues it (one past the cap, which only new arrivals
    /// check).
    pub(super) async fn queue_or_refuse(
        self: &Arc<Self>,
        pending: PendingOpen,
    ) -> Result<(), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let refused = {
            let staged = self.lock_staged();
            let mut q = self.lock_incoming();
            if staged.len() + q.len() >= self.negotiated.config.max_channels() {
                Some(pending)
            } else {
                q.push_back(pending);
                None
            }
        };
        if refused.is_none() {
            self.incoming_signal.notify(usize::MAX);
        }
        if let Some(pending) = refused {
            self.stage_incoming(pending).reject().await?;
        }
        Ok(())
    }

    /// Act on the device withdrawing an OPEN (a CLSE that names no local
    /// id), wherever the request has got to by now.
    ///
    /// Every place the request can live is searched under one lock
    /// order (channels, then staged, then incoming — the same order
    /// accept and `Drop` take): a racing accept may have installed the
    /// slot after this packet was classified, so the slot is looked for
    /// again here; otherwise the staged holder is flagged and the
    /// request dropped from the queue. There is no gap in which the
    /// withdrawal finds the request nowhere.
    pub(super) fn withdraw_open(&self, remote: RemoteId) {
        let mut chs = self.lock_channels();
        let staged = self.lock_staged();
        let mut incoming = self.lock_incoming();
        let closed = chs.close_remote(remote);
        if closed.is_none() {
            incoming.withdraw(remote);
            // A request staged out of the queue is cancelled
            // through its flag: the verdict observes it.
            for (id, flag) in staged.iter() {
                if *id == remote {
                    flag.store(true, Ordering::Relaxed);
                }
            }
        }
        drop(incoming);
        drop(staged);
        drop(chs);
        if let Some(idx) = closed {
            if let Some(signal) = self.signals.get(idx) {
                signal.wake();
            }
        }
    }

    /// Mark the connection ended and wake every waiter to see it.
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake_all();
    }

    fn wake_all(&self) {
        for signal in &self.signals {
            signal.wake();
        }
        self.incoming_signal.notify(usize::MAX);
        self.receive_signal.notify(usize::MAX);
    }

    /// Resolve once a receive in flight has something to give way to. A
    /// write abandoned mid-packet left the device waiting for the rest
    /// of it, so nothing may ever come; or the device is owed something
    /// that, with reads leaving it alone, nothing else may ever send.
    ///
    /// `raced` says a read is raced against this. Otherwise it is only
    /// asked before each read, with nothing to wake, which spares the
    /// transports that cannot be raced a listener for every read.
    pub(super) async fn receive_interrupted(&self, raced: bool) {
        let mut listener: Option<EventListener> = None;
        loop {
            if self.desync.check::<Infallible>().is_err() || !self.lock_owed().is_empty() {
                return;
            }
            if !raced {
                core::future::pending::<()>().await;
            }
            // Register, then look once more before waiting, as reads do.
            match listener.take() {
                Some(waiting) => waiting.await,
                None => listener = Some(self.receive_signal.listen()),
            }
        }
    }

    /// Fail once waiting can no longer end well: a write abandoned
    /// mid-packet desynchronized the connection, or it ended and nothing
    /// will be dispatched any more.
    pub(super) fn check_live<E>(&self) -> Result<(), Error<E>> {
        self.desync.check()?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        Ok(())
    }

    /// Take the write half for the caller's own packet, and nothing
    /// more: for a call that promises its wait is safe to drop, which
    /// it would not be with anything written along the way.
    ///
    /// Its packet is another matter, and so a call dropped on a stalled
    /// transport goes the way of any abandoned write once it gets that
    /// far. What the wait keeps from happening is a call that has
    /// nothing of its own to send being caught writing someone else's.
    pub(super) async fn lock_write_half(&self) -> WriteLock<'_, WH> {
        WriteLock {
            guard: self.write_half.lock().await,
            shared: self,
        }
    }

    /// Take the write half for one packet, once what is owed is out.
    ///
    /// A debt leaves the list only once it is on the wire, so a call
    /// dropped on its way there has lost nothing. Past the wait for the
    /// write half a drop abandons a packet, which is a desync as ever.
    pub(super) async fn lock_write(
        &self,
    ) -> Result<WriteLock<'_, WH>, Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let mut lock = self.lock_write_half().await;
        loop {
            let owed = self.lock_owed().front().copied();
            let Some(debt) = owed else {
                return Ok(lock);
            };
            let paid = match debt {
                Owed::Okay(ack) => {
                    send_okay_to(
                        &mut *lock,
                        &self.desync,
                        ack,
                        self.negotiated.ack_mode(),
                        self.negotiated.checksum(),
                    )
                    .await
                }
                Owed::Close(ids) => {
                    send_pkt(
                        &mut *lock,
                        &self.desync,
                        &Packet::close(ids),
                        self.negotiated.checksum(),
                    )
                    .await
                }
            };
            match paid {
                Ok(()) => drop(self.lock_owed().pop_front()),
                // Nothing reaches a device that is gone, so it is owed
                // nothing, and what it sent is still to be received.
                Err(e) if connection_gone(&e) => {
                    self.lock_owed().clear();
                    return Ok(lock);
                }
                Err(e) => return Err(e),
            }
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
            self.shared.owe(Owed::Close(ids));
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
        {
            let mut chs = self.shared.lock_channels();
            if let Some(slot) = chs.get_mut(self.ch) {
                slot.send_queue().finish();
                if !self.committed {
                    slot.refund(self.n);
                }
            }
        }
        if self.committed {
            return;
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
