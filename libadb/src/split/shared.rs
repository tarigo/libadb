use alloc::sync::Arc;
use async_lock::Mutex as AsyncMutex;
use core::convert::Infallible;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::Poll;
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

    pub(super) fn wake(&self) {
        self.event.notify(usize::MAX);
    }
}

pub(crate) struct Shared<WH> {
    pub(super) write_half: AsyncMutex<WH>,
    channels: Mutex<ChannelTable>,
    pub(super) signals: Box<[FlowSignal]>,
    pub(super) negotiated: Negotiated,
    pub(super) desync: DesyncFlag,
    incoming: Mutex<IncomingQueue>,
    staged: Mutex<Vec<(RemoteId, Arc<AtomicBool>)>>,
    stopped: AtomicBool,
    stream_over: AtomicBool,
    ended_in_step: AtomicBool,
    pub(super) listeners: AtomicUsize,
    pub(super) incoming_signal: Event,
    receive_signal: Event,
    owed: Mutex<VecDeque<Owed>>,
}

#[derive(Clone, Copy)]
pub(super) enum Owed {
    Okay(PendingAck),
    Close(ChannelIds),
}

impl<WH> Shared<WH> {
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
            stream_over: AtomicBool::new(false),
            ended_in_step: AtomicBool::new(false),
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

    pub(super) fn owe(&self, debt: Owed) {
        self.lock_owed().push_back(debt);
        self.receive_signal.notify(usize::MAX);
    }

    pub(super) async fn pay(&self) -> Result<(), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        if self.check_live::<Infallible>().is_ok() && !self.lock_owed().is_empty() {
            drop(self.lock_write().await?);
        }
        Ok(())
    }

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

    pub(super) async fn take_buffered(
        &self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<Option<usize>, Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        loop {
            {
                let mut chs = self.lock_channels();
                if !chs.get(ch).is_some_and(ChannelSlot::has_data) {
                    self.check_in_step()?;
                }
                let slot = chs.get_mut(ch).ok_or(Error::ChannelClosed)?;
                if self.check_live::<Infallible>().is_err() || !slot.take_acks(buf.len()) {
                    return slot.take_buffered(buf);
                }
            }
            self.until(Self::has_ended, self.acknowledge_take(ch, buf.len()))
                .await;
        }
    }

    pub(super) async fn until<F: Future>(
        &self,
        over: impl Fn(&Self) -> bool,
        work: F,
    ) -> Option<F::Output> {
        if over(self) {
            return None;
        }
        let mut work = pin!(work);
        let mut reached = pin!(self.once(over));
        poll_fn(|cx| {
            if let Poll::Ready(done) = work.as_mut().poll(cx) {
                return Poll::Ready(Some(done));
            }
            reached.as_mut().poll(cx).map(|()| None)
        })
        .await
    }

    async fn acknowledge_take(&self, ch: ChannelId, want: usize)
    where
        WH: Write,
    {
        let mut wh = self.lock_write_half().await;
        let ack = self.check_live::<Infallible>().ok().and_then(|()| {
            let mut chs = self.lock_channels();
            chs.get_mut(ch)?.settle_take(want)
        });
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
    }

    pub(super) fn stage_incoming(self: &Arc<Self>, pending: PendingOpen) -> SplitIncoming<WH>
    where
        WH: Write,
    {
        self.hold_incoming(pending, &mut self.lock_staged())
    }

    pub(super) fn take_incoming(self: &Arc<Self>) -> Option<SplitIncoming<WH>>
    where
        WH: Write,
    {
        self.take_incoming_past(0)
    }

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

    pub(super) fn withdraw_open(&self, remote: RemoteId) {
        let mut chs = self.lock_channels();
        let staged = self.lock_staged();
        let mut incoming = self.lock_incoming();
        let closed = chs.close_remote(remote);
        if closed.is_none() {
            incoming.withdraw(remote);
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

    pub(super) fn end_stream(&self) {
        self.stream_over.store(true, Ordering::Release);
        self.stop();
    }

    pub(super) fn stop(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            let in_step = self.desync.check::<Infallible>().is_ok();
            self.ended_in_step.store(in_step, Ordering::Release);
        }
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

    pub(super) async fn receive_interrupted(&self, raced: bool) {
        let mut listener: Option<EventListener> = None;
        loop {
            if self.desync.check::<Infallible>().is_err() || !self.lock_owed().is_empty() {
                return;
            }
            if !raced {
                core::future::pending::<()>().await;
            }
            match listener.take() {
                Some(waiting) => waiting.await,
                None => listener = Some(self.receive_signal.listen()),
            }
        }
    }

    async fn once(&self, over: impl Fn(&Self) -> bool) {
        let mut listener: Option<EventListener> = None;
        loop {
            if over(self) {
                return;
            }
            match listener.take() {
                Some(waiting) => waiting.await,
                None => listener = Some(self.receive_signal.listen()),
            }
        }
    }

    fn has_ended(&self) -> bool {
        self.check_live::<Infallible>().is_err()
    }

    pub(super) fn clse_called_off(&self) -> bool {
        self.stream_over.load(Ordering::Acquire) || self.desync.check::<Infallible>().is_err()
    }

    pub(super) fn check_close<E>(&self) -> Result<(), Error<E>> {
        if self.stream_over.load(Ordering::Acquire) {
            self.check_in_step()
        } else {
            self.desync.check()
        }
    }

    pub(super) fn check_live<E>(&self) -> Result<(), Error<E>> {
        self.check_in_step()?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        Ok(())
    }

    pub(super) fn check_in_step<E>(&self) -> Result<(), Error<E>> {
        let in_step = self.desync.check();
        if in_step.is_err() && self.ended_in_step.load(Ordering::Acquire) {
            return Ok(());
        }
        in_step
    }

    pub(super) async fn lock_write_half(&self) -> WriteLock<'_, WH> {
        WriteLock {
            guard: self.write_half.lock().await,
            shared: self,
        }
    }

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
                Err(e) if connection_gone(&e) => {
                    self.lock_owed().clear();
                    return Ok(lock);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

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
