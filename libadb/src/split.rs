//! Full-duplex Reader/Writer pair for a Connection whose transport is
//! [`Splittable`](crate::Splittable).
//!
//! `Reader` owns the read half and drives packet reception; `Writer`
//! owns a cheap handle to the shared write-half + channel table and can
//! be cloned for use from other threads/tasks. Read-path and write-path
//! never hold the same mutex concurrently, so a thread blocked in
//! [`Reader::read_channel`] does not prevent another thread from calling
//! [`Writer::write_channel`] or [`Writer::close_channel`].
//!
//! # Driving the connection
//!
//! There are two ways to use the pair:
//!
//! * **Reader-driven.** One task keeps the `Reader` and calls
//!   [`Reader::open_channel`] and [`Reader::read_channel`] itself;
//!   writers send from anywhere. Packets for other channels are
//!   buffered while it waits, but only that task can collect them.
//! * **Dispatched.** [`Reader::run`] takes the `Reader` and does
//!   nothing but receive and dispatch packets, waking whoever waits on
//!   the channel each one is for. Every channel operation then goes
//!   through the `Writer` — [`Writer::open_channel`],
//!   [`Writer::read_channel`], [`Writer::write_channel`],
//!   [`Writer::close_channel`] — so any number of tasks can work on
//!   their own channels at once and none waits on another's traffic.
//!   Channels the device opens (`adb reverse`) are taken through an
//!   [`IncomingListener`] from [`Writer::listen_incoming`].
//!
//! Once the `Reader` is gone — `run` returned or the `Reader` was
//! dropped — every `Writer` call that waits on the device fails with
//! [`Error::Disconnected`] instead of waiting for packets nobody reads:
//! opening a channel, reading one, waiting for send credit, accepting
//! one the device opened. Calls that need no answer — a write the
//! credit already covers, a close — still reach the transport.
//!
//! Available under the `split` feature (implied by every runtime
//! feature: `tokio`, `smol`, `nusb`, `rusb`). Pulls `std` into the
//! build for its sync primitives; a pure `no_std` variant would need a
//! no_std Mutex implementation and is not yet provided.
//!
//! # Close ↔ read coordination
//!
//! Because only the `Reader` drives packet reception, calling
//! [`Writer::close_channel`] does not by itself wake a concurrent
//! [`Reader::read_channel`] parked on the same channel: the reader
//! unblocks only once it receives the device's echoed `CLSE` packet.
//! If the device is slow or non-conformant and never echoes the close,
//! an in-flight `read_channel` can remain blocked until the transport
//! itself fails. Drop the `Reader` (or fail the transport) to unblock
//! such a reader unconditionally.

#![cfg(feature = "split")]

use alloc::sync::Arc;
use async_lock::Mutex as AsyncMutex;
use bytes::BytesMut;
use core::convert::Infallible;
use core::future::{poll_fn, Future};
use core::pin::{pin, Pin};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::task::Poll;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use event_listener::{Event, EventListener};
use std::sync::Mutex;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::base::channel::{
    channel_ids_of, close_remote, dispatch_packet, slot_for, slot_for_mut, ChannelFault, ChannelId,
    ChannelSlot, ChannelState, DispatchOutcome, PendingAck, PendingOpen, SelectResult,
};
use crate::base::connection::ConnectionConfig;
use crate::base::error::Error;
use crate::base::ids::{ChannelIds, LocalId, RemoteId};
use crate::base::negotiated::Negotiated;
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::wire::{recv_pkt, send_okay_to, send_pkt, send_raw, DesyncFlag};
use crate::device_banner::DeviceBanner;

pub(crate) struct FlowSignal {
    event: Event,
}

impl FlowSignal {
    pub(crate) const fn new() -> Self {
        Self {
            event: Event::new(),
        }
    }

    fn listen(&self) -> EventListener {
        self.event.listen()
    }

    /// Wake every writer parked on this channel.
    ///
    /// Waking is only a prompt to look again: admission is decided by
    /// the slot's send queue, so writers that are not at its head check
    /// their place and park right back. That keeps credit impossible to
    /// lose to a missed or stolen notification — order lives in data
    /// under the channels mutex, not in wake delivery.
    fn wake(&self) {
        self.event.notify(usize::MAX);
    }
}

pub(crate) struct Shared<WH> {
    pub(crate) write_half: AsyncMutex<WH>,
    pub(crate) channels: Mutex<Box<[Option<ChannelSlot>]>>,
    /// One per slot of `channels`.
    pub(crate) signals: Box<[FlowSignal]>,
    pub(crate) negotiated: Negotiated,
    pub(crate) local_id_counter: AtomicU32,
    pub(crate) desync: DesyncFlag,
    /// Device-initiated OPENs awaiting [`Reader::accept_incoming`].
    pub(crate) incoming: Mutex<VecDeque<PendingOpen>>,
    /// Requests staged out of the queue in an owned [`SplitIncoming`],
    /// by remote id — the only place a device cancellation can still
    /// reach them once they have left `incoming`.
    pub(crate) staged: Mutex<Vec<(RemoteId, Arc<AtomicBool>)>>,
    /// Set once the [`Reader`] is gone: nothing will dispatch packets
    /// any more, so waiting for one would never end.
    pub(crate) stopped: AtomicBool,
    /// Live [`IncomingListener`]s. While there is one, [`Reader::run`]
    /// keeps device-initiated OPENs for it instead of refusing them.
    pub(crate) listeners: AtomicUsize,
    /// Woken when an OPEN is queued, for [`IncomingListener::accept`].
    pub(crate) incoming_signal: Event,
    /// CLSEs for channels the device accepted just as their opener gave
    /// up: `Drop` cannot send them, so whoever takes the write half
    /// next does.
    pub(crate) owed_closes: Mutex<Vec<ChannelIds>>,
}

impl<WH> Shared<WH> {
    fn next_local_id(&self) -> LocalId {
        loop {
            let id = self.local_id_counter.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return LocalId::from(id);
            }
        }
    }

    fn lock_channels(&self) -> std::sync::MutexGuard<'_, Box<[Option<ChannelSlot>]>> {
        self.channels.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_incoming(&self) -> std::sync::MutexGuard<'_, VecDeque<PendingOpen>> {
        self.incoming.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_staged(&self) -> std::sync::MutexGuard<'_, Vec<(RemoteId, Arc<AtomicBool>)>> {
        self.staged.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_owed(&self) -> std::sync::MutexGuard<'_, Vec<ChannelIds>> {
        self.owed_closes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve a free slot and send OPEN for `destination` — the start
    /// both openers share. The guard frees the slot unless the opener
    /// disarms it once the device answers.
    async fn send_open(
        self: &Arc<Self>,
        destination: &[u8],
    ) -> Result<(ChannelId, SlotGuard<WH>), Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        let (slot, local_id) = {
            let mut chs = self.lock_channels();
            let idx = chs
                .iter()
                .position(|s| s.is_none())
                .ok_or(Error::NoFreeChannels)?;
            let id = self.next_local_id();
            chs[idx] = Some(ChannelSlot::opening(id, self.negotiated.rx_policy()));
            (idx, id)
        };
        let guard = SlotGuard::new(Arc::clone(self), slot);

        let open_arg1 = self.negotiated.advertised_credit().unwrap_or(0);
        let pkt = Packet::new(
            Command::Open,
            local_id.raw(),
            open_arg1,
            destination.to_vec(),
        );
        {
            let mut wh = self.lock_write().await?;
            send_pkt(&mut *wh, &self.desync, &pkt, self.negotiated.checksum()).await?;
        }
        Ok((
            ChannelId {
                slot,
                local: local_id,
            },
            guard,
        ))
    }

    /// Close a channel a packet broke on its own: its calls fail with
    /// `fault` from now on, and the device gets its CLSE. The CLSE goes
    /// out even when the slot is gone by now — an opener given up on in
    /// the meantime took it, and the device still holds its end; a
    /// second CLSE for a channel already closed is one adbd ignores.
    async fn fail_channel(
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
            slot_for_mut(&mut chs, ch).map(|s| s.fail(fault)).is_some()
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
    async fn take_buffered(
        &self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<Option<usize>, Error<<WH as ErrorType>::Error>>
    where
        WH: Write,
    {
        {
            let mut chs = self.lock_channels();
            let slot = slot_for_mut(&mut chs, ch).ok_or(Error::ChannelClosed)?;
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
            let slot = slot_for_mut(&mut chs, ch).ok_or(Error::ChannelClosed)?;
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

    async fn send_okay(&self, ack: PendingAck) -> Result<(), Error<<WH as ErrorType>::Error>>
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
    fn stage_incoming(self: &Arc<Self>, pending: PendingOpen) -> SplitIncoming<WH>
    where
        WH: Write,
    {
        self.hold_incoming(pending, &mut self.lock_staged())
    }

    /// Take the oldest queued device-initiated OPEN into its owned
    /// holder.
    fn take_incoming(self: &Arc<Self>) -> Option<SplitIncoming<WH>>
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
    fn take_incoming_past(self: &Arc<Self>, cap: usize) -> Option<SplitIncoming<WH>>
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
    fn stop(&self) {
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
    fn check_live<E>(&self) -> Result<(), Error<E>> {
        self.desync.check()?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        Ok(())
    }

    /// Take the write half for one packet, once the owed CLSEs are out.
    async fn lock_write(&self) -> Result<WriteLock<'_, WH>, Error<<WH as ErrorType>::Error>>
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
struct WriteLock<'a, WH> {
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

struct SlotGuard<WH> {
    shared: Arc<Shared<WH>>,
    idx: usize,
    armed: bool,
}

impl<WH> SlotGuard<WH> {
    fn new(shared: Arc<Shared<WH>>, idx: usize) -> Self {
        Self {
            shared,
            idx,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<WH> Drop for SlotGuard<WH> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut chs = self.shared.lock_channels();
        let Some(slot) = chs.get_mut(self.idx).and_then(Option::take) else {
            return;
        };
        // The device accepted before the opener gave up: its end is
        // open, and the CLSE for it is owed to whoever writes next.
        if let Some(ids) = slot.ids().filter(|_| !slot.is_failed()) {
            self.shared.lock_owed().push(ids);
        }
    }
}

struct CreditGuard<'a, WH> {
    shared: &'a Shared<WH>,
    ch: ChannelId,
    n: usize,
    committed: bool,
}

impl<'a, WH> CreditGuard<'a, WH> {
    fn new(shared: &'a Shared<WH>, ch: ChannelId, n: usize) -> Self {
        Self {
            shared,
            ch,
            n,
            committed: false,
        }
    }

    fn commit(&mut self) {
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
            if let Some(slot) = slot_for_mut(&mut chs, self.ch) {
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
struct QueueGuard<'a, WH> {
    shared: &'a Shared<WH>,
    ch: ChannelId,
    place: u64,
    served: bool,
}

impl<WH> Drop for QueueGuard<'_, WH> {
    fn drop(&mut self) {
        if self.served {
            return;
        }
        let head_moved = {
            let mut chs = self.shared.lock_channels();
            match slot_for_mut(&mut chs, self.ch) {
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

/// What a fault confined to one channel — data past its receive cap, a
/// READY it cannot take — costs the call that dispatched it.
#[derive(Clone, Copy)]
enum OnFault {
    /// Fail the call, whichever channel it is on, as on a
    /// [`Connection`](crate::Connection): the reader-driven contract.
    FailCall,
    /// Close that channel alone and carry on: what [`Reader::run`]
    /// does, since its failing would take every channel down.
    CloseChannel,
}

/// Read half of a split [`Connection`](crate::Connection).
///
/// Drives packet reception, dispatching OKAY/CLSE/WRTE packets for all
/// channels. Only one Reader exists per connection.
pub struct Reader<RH, WH>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    read_half: RH,
    recv_buf: BytesMut,
    shared: Arc<Shared<WH>>,
}

impl<RH, WH> Reader<RH, WH>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    pub(crate) fn new(read_half: RH, recv_buf: BytesMut, shared: Arc<Shared<WH>>) -> Self {
        Self {
            read_half,
            recv_buf,
            shared,
        }
    }

    /// Maximum payload size for outbound packets.
    pub fn max_payload(&self) -> u32 {
        self.shared.negotiated.max_payload
    }

    /// Resource limits this connection was opened with.
    pub fn config(&self) -> &ConnectionConfig {
        &self.shared.negotiated.config
    }

    /// Protocol version in effect: `min(ADB_VERSION, device version)`.
    pub fn protocol_version(&self) -> u32 {
        self.shared.negotiated.protocol_version
    }

    /// Whether delayed-ACK flow control was negotiated.
    pub fn delayed_ack(&self) -> bool {
        self.shared.negotiated.delayed_ack
    }

    /// Raw device banner bytes from the CNXN handshake.
    pub fn device_banner(&self) -> Option<&[u8]> {
        self.shared
            .negotiated
            .device_banner
            .as_ref()
            .map(|b| b.raw())
    }

    /// Parsed device banner from the CNXN handshake.
    pub fn device_banner_parsed(&self) -> Option<&DeviceBanner> {
        self.shared.negotiated.device_banner.as_ref()
    }

    /// Fail with [`Error::MissingFeature`] if the device banner was
    /// parsed and does not list `feature`. Permissive when no banner
    /// is available.
    pub fn require_feature(
        &self,
        feature: crate::protocol::features::Feature,
    ) -> Result<(), Error<<RH as ErrorType>::Error>> {
        self.shared.negotiated.require_feature(feature)
    }

    /// Open a channel to `destination`.
    ///
    /// Sends OPEN and waits for the matching OKAY (while dispatching any
    /// unrelated packets that arrive in the meantime).
    ///
    /// **Not cancellation-safe.** Dropping the future after the OPEN
    /// packet has been sent gives the channel up before the device
    /// answers. Should it accept after all, the next call that reads
    /// the connection answers its READY with CLSE, so the device's end
    /// does not stay open; the same goes for an `Err` returned before
    /// the answer.
    pub async fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<<RH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        let (ch, mut guard) = self.shared.send_open(destination).await?;
        self.await_open_ack(ch, &mut guard).await
    }

    /// Refuse queued OPENs past the cap — what a cancelled overflow
    /// refusal left behind — before taking any new packet in. The
    /// intake loops that can run with a full queue start here, so
    /// repeated cancellation cannot grow the queue beyond one past the
    /// cap: nothing new is read until the leftover is answered.
    /// (`accept_incoming` needs no barrier — it only reads with the
    /// queue empty.)
    async fn drain_overflow(&mut self) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let cap = self.shared.negotiated.config.max_channels();
        while let Some(excess) = self.shared.take_incoming_past(cap) {
            excess.reject().await?;
        }
        Ok(())
    }

    async fn await_open_ack(
        &mut self,
        ch: ChannelId,
        guard: &mut SlotGuard<WH>,
    ) -> Result<ChannelId, Error<<RH as ErrorType>::Error>> {
        self.drain_overflow().await?;
        loop {
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.negotiated.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Ready if pkt.arg1 == ch.local.raw() => {
                    let remote = RemoteId::from(pkt.arg0);
                    let accepted = {
                        let mut chs = self.shared.lock_channels();
                        match chs[ch.slot].as_mut() {
                            Some(slot) => slot.accept_open_ready(remote, &pkt.data),
                            None => Ok(()),
                        }
                    };
                    if let Err(e) = accepted {
                        // The device holds an end it takes for open.
                        let fault = ChannelFault::Protocol(e);
                        let ids = ChannelIds {
                            local: ch.local,
                            remote,
                        };
                        self.shared.fail_channel(ch.slot, ids, fault).await?;
                        return Err(fault.error());
                    }
                    guard.disarm();
                    return Ok(ch);
                }
                Command::Close if pkt.arg1 == ch.local.raw() => {
                    return Err(Error::ChannelClosed);
                }
                _ => self.dispatch(pkt, OnFault::FailCall).await?,
            }
        }
    }

    /// Receive and dispatch packets until the connection fails.
    ///
    /// Meant to run as a task of its own for as long as the connection
    /// is used: it wakes whoever waits on the channel each packet is
    /// for, and every channel operation goes through the [`Writer`]
    /// meanwhile — see [Driving the connection](crate::split#driving-the-connection).
    /// It returns only with the error that ended reception, which is
    /// why its `Ok` side is [`Infallible`]; the `Reader` is gone then,
    /// and waiters on the `Writer` get [`Error::Disconnected`].
    ///
    /// Channels the device opens toward the host (`adb reverse`) wait
    /// for an [`IncomingListener`] while one is alive, and are refused
    /// otherwise: nobody would accept them. Requests still queued when
    /// the last listener goes are refused once the next packet arrives.
    ///
    /// A packet that breaks one channel alone — data past its receive
    /// cap, a READY it cannot take — closes that channel: the device
    /// gets its CLSE, and the channel's calls fail with that error
    /// (once what it buffered before is read) rather than end
    /// reception for every channel.
    ///
    /// Without delayed ACK, data is acknowledged from here as it
    /// arrives, so the acknowledgement may reach the device after
    /// packets a task sends in response to that data. The protocol
    /// allows either order.
    ///
    /// Reception is never cancelled from within, so this is also the
    /// way to read a transport whose reads are not cancel-safe (USB)
    /// from several tasks. Dropping the future stops reception like
    /// any dropped read on such a transport, and is otherwise the way
    /// to shut the connection down.
    pub async fn run(mut self) -> Result<Infallible, Error<<RH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        loop {
            // Before every receive, the first included, so nothing left
            // over — from before `run` or by the last packet — waits for
            // traffic that may never come: owed CLSEs go out, and
            // requests nobody listens for are refused.
            let owes = !self.shared.lock_owed().is_empty();
            if owes {
                drop(self.shared.lock_write().await?);
            }
            if self.shared.listeners.load(Ordering::Acquire) == 0 {
                while let Some(refused) = self.shared.take_incoming() {
                    refused.reject().await?;
                }
            }
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.negotiated.config.max_payload(),
            )
            .await?;
            self.dispatch(pkt, OnFault::CloseChannel).await?;
        }
    }

    /// Read from channel `ch` into `buf`. Returns the number of bytes read.
    ///
    /// Returns immediately if data is already buffered; otherwise blocks
    /// reading packets until a WRTE for `ch` arrives (dispatching packets
    /// for other channels in the meantime).
    ///
    /// A concurrent [`Writer::close_channel`] on the same channel does
    /// not wake this call directly — see the module-level note on
    /// close ↔ read coordination.
    pub async fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<<RH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        if let Some(n) = self.shared.take_buffered(ch, buf).await? {
            return Ok(n);
        }

        let ids = self.channel_ids(ch)?;

        self.drain_overflow().await?;
        loop {
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.negotiated.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Write if pkt.arg1 == ids.local.raw() => {
                    let n = buf.len().min(pkt.data.len());
                    buf[..n].copy_from_slice(&pkt.data[..n]);
                    let ack = {
                        let mut chs = self.shared.lock_channels();
                        match slot_for_mut(&mut chs, ch) {
                            Some(slot) => slot.deliver(&pkt.data, n)?,
                            None => None,
                        }
                    };
                    if let Some(ack) = ack {
                        self.shared.send_okay(ack).await?;
                    }
                    return Ok(n);
                }
                Command::Close if ids.closed_by(&pkt) => {
                    {
                        let mut chs = self.shared.lock_channels();
                        if let Some(slot) = slot_for_mut(&mut chs, ch) {
                            slot.apply_close();
                        }
                    }
                    if let Some(signal) = self.shared.signals.get(ch.slot) {
                        signal.wake();
                    }
                    return Err(Error::ChannelClosed);
                }
                _ => self.dispatch(pkt, OnFault::FailCall).await?,
            }
        }
    }

    fn channel_ids(&self, ch: ChannelId) -> Result<ChannelIds, Error<<RH as ErrorType>::Error>> {
        let chs = self.shared.lock_channels();
        channel_ids_of(&chs, ch)
    }

    /// Wait for a device-initiated channel (`adb reverse` traffic and
    /// the like) and hand it over for a verdict.
    ///
    /// Packets for other channels keep being dispatched while waiting.
    /// The returned [`SplitIncoming`] owns the request — it does not
    /// borrow the reader, so it can be held across other calls until
    /// [`accept`](SplitIncoming::accept) or
    /// [`reject`](SplitIncoming::reject) resolves it; dropping it
    /// undecided puts the request back at the head of the queue.
    ///
    /// Dropping the future while it still *waits* for a packet is
    /// another matter: the wait is a transport read, so cancelling it
    /// inherits the transport's
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety) — where
    /// reads are not cancel-safe (USB), an abandoned in-flight read can
    /// lose packet bytes, exactly as with a cancelled
    /// [`read_channel`](Self::read_channel).
    pub async fn accept_incoming(
        &mut self,
    ) -> Result<SplitIncoming<WH>, Error<<RH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        loop {
            if let Some(incoming) = self.shared.take_incoming() {
                return Ok(incoming);
            }
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.negotiated.config.max_payload(),
            )
            .await?;
            self.dispatch(pkt, OnFault::FailCall).await?;
        }
    }

    /// [`accept_incoming`](Self::accept_incoming) without waiting:
    /// takes a request that already arrived, if any.
    pub fn try_accept_incoming(&mut self) -> Option<SplitIncoming<WH>> {
        self.shared.take_incoming()
    }

    async fn dispatch(
        &mut self,
        pkt: Packet,
        on_fault: OnFault,
    ) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let outcome = {
            let mut chs = self.shared.lock_channels();
            dispatch_packet(&mut chs, &pkt)
        };

        match outcome {
            DispatchOutcome::AckWrite { idx, ack } => {
                self.shared.signals[idx].wake();
                self.shared.send_okay(ack).await?;
            }
            DispatchOutcome::CreditGranted { idx }
            | DispatchOutcome::SlotClosed { idx }
            | DispatchOutcome::DataBuffered { idx } => {
                self.shared.signals[idx].wake();
            }
            DispatchOutcome::IncomingOpen {
                remote,
                credit,
                destination,
            } => {
                // Bounded by the channel table: past that, an OPEN
                // storm is refused on arrival rather than remembered.
                // Held holders spend the same budget as queued
                // requests — otherwise an application sitting on
                // holders would drain the queue and let payloads
                // accumulate without limit.
                let pending = PendingOpen {
                    remote,
                    credit,
                    destination,
                };
                let refused = {
                    let staged = self.shared.lock_staged();
                    let mut q = self.shared.lock_incoming();
                    if staged.len() + q.len() >= self.shared.negotiated.config.max_channels() {
                        Some(pending)
                    } else {
                        q.push_back(pending);
                        None
                    }
                };
                if refused.is_none() {
                    self.shared.incoming_signal.notify(usize::MAX);
                }
                if let Some(pending) = refused {
                    // The refusal owes adbd a CLSE, and waiting for the
                    // write lock is a cancellation point: dropped
                    // there, the OPEN would vanish unanswered with the
                    // connection still healthy. Hand it to the verdict
                    // machinery instead — reject() keeps the request
                    // recoverable until CLSE is committed, and its Drop
                    // re-queues it (one past the cap, which only new
                    // arrivals check).
                    self.shared.stage_incoming(pending).reject().await?;
                }
            }
            DispatchOutcome::CancelPendingOpen { remote } => {
                // Every place the request can live, under one lock
                // order (channels, then staged, then incoming — the
                // same order accept and Drop take): a racing accept
                // may have installed the slot after this packet was
                // classified, so look for it again here; otherwise
                // flag the staged holder and drop it from the queue.
                // There is no gap in which the withdrawal finds the
                // request nowhere.
                let mut chs = self.shared.lock_channels();
                let staged = self.shared.lock_staged();
                let mut incoming = self.shared.lock_incoming();
                let closed = close_remote(&mut chs, remote);
                if closed.is_none() {
                    incoming.retain(|p| p.remote != remote);
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
                    if let Some(signal) = self.shared.signals.get(idx) {
                        signal.wake();
                    }
                }
            }
            DispatchOutcome::StrayReady { ids } => {
                let mut wh = self.shared.lock_write().await?;
                send_pkt(
                    &mut *wh,
                    &self.shared.desync,
                    &Packet::close(ids),
                    self.shared.negotiated.checksum(),
                )
                .await?;
            }
            DispatchOutcome::ChannelFault {
                idx,
                ids,
                opening,
                fault,
            } => {
                // An opener waits on its slot whoever drives the
                // connection, and the device holds an end it takes for
                // open: under either policy both have to hear of it.
                if opening || matches!(on_fault, OnFault::CloseChannel) {
                    self.shared.fail_channel(idx, ids, fault).await?;
                }
                if matches!(on_fault, OnFault::FailCall) {
                    return Err(fault.error());
                }
            }
            DispatchOutcome::Unmatched => {}
        }
        Ok(())
    }

    /// Send CLSE and release the channel slot —
    /// [`Writer::close_channel`] reachable from the read half, so an
    /// open-read-close service exchange can run on the `Reader` alone.
    pub async fn close_channel(
        &self,
        ch: ChannelId,
    ) -> Result<(), Error<<RH as ErrorType>::Error>> {
        close_channel_via(&self.shared, ch).await
    }
}

impl<RH, WH> Drop for Reader<RH, WH>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    fn drop(&mut self) {
        self.shared.stop();
    }
}

/// A device-initiated channel awaiting a verdict, on a split
/// connection. Owns the request — holding it does not borrow the
/// [`Reader`]. Dropping it undecided puts the request back at the head
/// of the queue.
pub struct SplitIncoming<WH>
where
    WH: Write,
{
    shared: Arc<Shared<WH>>,
    pending: Option<PendingOpen>,
    /// A slot reserved by `accept` before READY is on the wire. If the
    /// future is cancelled or errors before that, `Drop` frees it —
    /// otherwise a cancelled accept would occupy it forever.
    reserved: Option<usize>,
    /// Set by the reader when the device withdraws this OPEN (a CLSE
    /// naming no local id) while the request is staged here.
    cancelled: Arc<AtomicBool>,
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
        let checksum = shared.negotiated.checksum();

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
            chs.iter().position(|s| s.is_none()).map(|idx| {
                let ids = ChannelIds {
                    local: shared.next_local_id(),
                    remote,
                };
                let policy = shared.negotiated.rx_policy();
                chs[idx] = Some(ChannelSlot::accepted(ids, credit, policy));
                (idx, ids.local)
            })
        };
        let Some((slot_idx, local_id)) = reserved else {
            // No slot to give: refuse, and consume the request.
            let mut wh = shared.lock_write().await?;
            send_pkt(&mut *wh, &shared.desync, &Packet::refuse(remote), checksum).await?;
            self.pending.take();
            return Err(Error::NoFreeChannels);
        };
        // Armed for rollback until READY is committed.
        self.reserved = Some(slot_idx);

        let payload = match shared.negotiated.advertised_credit() {
            Some(credit) => credit.to_le_bytes().to_vec(),
            None => Vec::new(),
        };
        {
            let mut wh = shared.lock_write().await?;
            send_pkt(
                &mut *wh,
                &shared.desync,
                &Packet::new(Command::Ready, local_id.raw(), remote.raw(), payload),
                checksum,
            )
            .await?;
        }

        // READY is out: the slot is committed and the request consumed.
        self.reserved = None;
        self.pending.take();
        Ok(ChannelId {
            slot: slot_idx,
            local: local_id,
        })
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
    /// A request the device has withdrawn in the meantime is consumed
    /// silently: it no longer expects an answer.
    pub async fn reject(mut self) -> Result<(), Error<<WH as ErrorType>::Error>> {
        if self.cancelled.load(Ordering::Relaxed) {
            self.pending.take();
            return Ok(());
        }
        let remote = self.pending.as_ref().expect("undecided").remote;
        let shared = Arc::clone(&self.shared);
        let checksum = shared.negotiated.checksum();
        {
            let mut wh = shared.lock_write().await?;
            send_pkt(&mut *wh, &shared.desync, &Packet::refuse(remote), checksum).await?;
        }
        self.pending.take();
        Ok(())
    }
}

impl<WH> Drop for SplitIncoming<WH>
where
    WH: Write,
{
    fn drop(&mut self) {
        // A slot reserved but never confirmed by READY: release it.
        if let Some(idx) = self.reserved.take() {
            if let Some(slot) = self.shared.lock_channels().get_mut(idx) {
                *slot = None;
            }
        }
        // Unregister and requeue under both locks at once, in the same
        // staged-then-incoming order the cancel dispatch takes: a
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

/// Write half of a split [`Connection`](crate::Connection).
///
/// Cheaply cloneable (an `Arc` bump). Methods take `&self`, so a single
/// `Writer` can be shared across threads with no additional wrapping.
pub struct Writer<WH>
where
    WH: Write,
{
    shared: Arc<Shared<WH>>,
}

impl<WH> Clone for Writer<WH>
where
    WH: Write,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<WH> Writer<WH>
where
    WH: Write,
{
    pub(crate) fn new(shared: Arc<Shared<WH>>) -> Self {
        Self { shared }
    }

    /// Maximum payload size for outbound packets.
    pub fn max_payload(&self) -> u32 {
        self.shared.negotiated.max_payload
    }

    /// Resource limits this connection was opened with.
    pub fn config(&self) -> &ConnectionConfig {
        &self.shared.negotiated.config
    }

    /// Whether delayed-ACK flow control was negotiated.
    pub fn delayed_ack(&self) -> bool {
        self.shared.negotiated.delayed_ack
    }

    /// Protocol version in effect: `min(ADB_VERSION, device version)`.
    pub fn protocol_version(&self) -> u32 {
        self.shared.negotiated.protocol_version
    }

    /// Raw device banner bytes from the CNXN handshake.
    ///
    /// Lock-free connection metadata — available even while the
    /// [`Reader`] is blocked in a read on another thread.
    pub fn device_banner(&self) -> Option<&[u8]> {
        self.shared
            .negotiated
            .device_banner
            .as_ref()
            .map(|b| b.raw())
    }

    /// Parsed device banner from the CNXN handshake.
    ///
    /// Lock-free connection metadata — available even while the
    /// [`Reader`] is blocked in a read on another thread.
    pub fn device_banner_parsed(&self) -> Option<&DeviceBanner> {
        self.shared.negotiated.device_banner.as_ref()
    }

    /// Everything the handshake settled, for the crate's own helpers.
    pub(crate) fn negotiated(&self) -> &Negotiated {
        &self.shared.negotiated
    }

    /// Take the channels the device opens toward the host (`adb
    /// reverse`) on a connection whose [`Reader::run`] dispatches
    /// packets. While the listener lives, `run` keeps them for its
    /// [`accept`](IncomingListener::accept) instead of refusing them.
    pub fn listen_incoming(&self) -> IncomingListener<WH> {
        self.shared.listeners.fetch_add(1, Ordering::AcqRel);
        IncomingListener {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Open a channel to `destination` on a connection whose
    /// [`Reader::run`] dispatches packets.
    ///
    /// Sends OPEN and waits until the device accepts or refuses it;
    /// a refusal comes back as [`Error::ChannelClosed`].
    ///
    /// **Not cancellation-safe.** Dropping the future after OPEN went
    /// out gives the channel up before the device answers. Should it
    /// accept after all, `run` answers its READY with CLSE; if `run`
    /// took that READY before the drop, the CLSE goes out with the
    /// next packet anyone writes or `run` receives. Either way the
    /// device's end does not stay open for long — unless the
    /// [`Reader`] is gone, and with it whatever would read the READY.
    pub async fn open_channel(
        &self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<<WH as ErrorType>::Error>> {
        self.shared.check_live()?;
        let (ch, mut guard) = self.shared.send_open(destination).await?;
        self.await_open_ack(ch, &mut guard).await
    }

    /// Wait for [`Reader::run`] to dispatch the device's answer to the
    /// OPEN `ch` was reserved for.
    async fn await_open_ack(
        &self,
        ch: ChannelId,
        guard: &mut SlotGuard<WH>,
    ) -> Result<ChannelId, Error<<WH as ErrorType>::Error>> {
        let signal = &self.shared.signals[ch.slot];
        loop {
            self.shared.desync.check()?;
            let listener = signal.listen();
            {
                let chs = self.shared.lock_channels();
                match slot_for(&chs, ch) {
                    Some(slot) => match slot.state() {
                        ChannelState::Opening => {}
                        // A remote id comes only with a READY the slot
                        // took: without one the device refused the OPEN,
                        // or answered it with a READY that failed the
                        // slot. With one the channel was opened, even if
                        // it has been closed since.
                        ChannelState::Closed if slot.ids().is_none() => {
                            return Err(slot.closed_error())
                        }
                        ChannelState::Open | ChannelState::Closed => {
                            guard.disarm();
                            return Ok(ch);
                        }
                    },
                    None => return Err(Error::ChannelClosed),
                }
            }
            self.shared.check_live()?;
            listener.await;
        }
    }

    /// Read from channel `ch` into `buf` on a connection whose
    /// [`Reader::run`] dispatches packets. Returns the number of bytes
    /// read.
    ///
    /// Returns at once with whatever is buffered, otherwise waits for
    /// the next WRTE on `ch`. A channel the device closed fails with
    /// [`Error::ChannelClosed`] once its buffered data is read.
    ///
    /// Cancellation-safe while it waits — for data, or for the write
    /// lock an acknowledgement needs: nothing has been taken then, and
    /// the data stays buffered for the next call. Dropping the future
    /// while that acknowledgement is written desynchronizes the
    /// connection, as with any cancelled write.
    pub async fn read_channel(
        &self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<<WH as ErrorType>::Error>> {
        match self
            .select_channel(ch, buf, core::future::pending::<Infallible>())
            .await?
        {
            SelectResult::Data(n) => Ok(n),
            SelectResult::Interrupted(never) => match never {},
        }
    }

    /// [`read_channel`](Self::read_channel), returning early with
    /// [`SelectResult::Interrupted`] if `interrupt` resolves while it
    /// waits for data.
    ///
    /// Buffered data wins over a ready interrupt, and the interrupt is
    /// only raced against the wait, never against the acknowledgement
    /// a read may send, so an interrupted call has taken nothing from
    /// the channel.
    pub async fn select_channel<F: Future>(
        &self,
        ch: ChannelId,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<<WH as ErrorType>::Error>> {
        let Some(signal) = self.shared.signals.get(ch.slot) else {
            return Err(Error::ChannelClosed);
        };
        let mut interrupt = pin!(interrupt);
        let mut listener: Option<EventListener> = None;
        loop {
            // Each time round: data that arrived just as another task
            // desynchronized the connection is not handed out.
            self.shared.desync.check()?;
            if let Some(n) = self.shared.take_buffered(ch, buf).await? {
                return Ok(SelectResult::Data(n));
            }
            self.shared.check_live()?;
            // Register, then look once more before waiting: data that
            // lands in between still wakes us, and a read that finds
            // data at once never registers at all.
            let Some(waiting) = listener.as_mut() else {
                listener = Some(signal.listen());
                continue;
            };
            let interrupted = poll_fn(|cx| {
                if let Poll::Ready(value) = interrupt.as_mut().poll(cx) {
                    return Poll::Ready(Some(value));
                }
                Pin::new(&mut *waiting).poll(cx).map(|()| None)
            })
            .await;
            listener = None;
            if let Some(value) = interrupted {
                return Ok(SelectResult::Interrupted(value));
            }
        }
    }

    /// Write `data` to the given channel.
    ///
    /// Splits `data` into chunks bounded by `max_payload` and the
    /// currently-granted send budget. Concurrent writers on the same
    /// channel never consume the same credit, and credit is granted in
    /// arrival order — a writer looping back for its next chunk queues
    /// behind the ones already waiting.
    ///
    /// The bytes of one call go out in order; concurrent calls on the
    /// same channel interleave at chunk granularity in unspecified
    /// order, like unsynchronized writes to one socket. A caller that
    /// needs whole messages on the wire serializes the calls itself,
    /// as the FFI shell does around each frame.
    ///
    /// **Not cancellation-safe.** Reserved-but-unsent credit is
    /// refunded when the future is dropped, but a packet goes out as a
    /// header write followed by a payload write, and dropping the
    /// future between them leaves the device reading whatever we send
    /// next as the rest of that packet. The connection is marked
    /// desynchronized instead: this and every other operation on it
    /// then fails with [`Error::Desynchronized`], including on the
    /// paired [`Reader`] and calls already waiting on a `Writer`. Close
    /// it and open a new one.
    ///
    /// The mark goes up from the moment the header write is first
    /// polled, not only between the two writes — a transport that took
    /// bytes before returning `Pending` looks no different from one
    /// that took none.
    pub async fn write_channel(
        &self,
        ch: ChannelId,
        data: &[u8],
    ) -> Result<(), Error<<WH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        if data.is_empty() {
            return Ok(());
        }
        let max = (self.shared.negotiated.max_payload as usize).max(1);
        let checksum = self.shared.negotiated.checksum();

        let mut offset = 0;
        while offset < data.len() {
            let want = (data.len() - offset).min(max);
            let n = self.acquire_credit(ch, want).await?;
            let mut guard = CreditGuard::new(&self.shared, ch, n);

            let ids = self.channel_ids(ch)?;
            let chunk = &data[offset..offset + n];

            {
                let mut wh = self.shared.lock_write().await?;
                send_raw(
                    &mut *wh,
                    &self.shared.desync,
                    Command::Write,
                    ids,
                    chunk,
                    checksum,
                )
                .await?;
            }
            guard.commit();
            offset += n;
        }
        Ok(())
    }

    /// Send CLSE and release the channel slot. Any cloned `Writer`
    /// parked on this channel observes `ChannelClosed` and unblocks.
    ///
    /// A concurrent [`Reader::read_channel`] on the same channel is
    /// not woken directly — see the module-level note on close ↔ read
    /// coordination.
    pub async fn close_channel(
        &self,
        ch: ChannelId,
    ) -> Result<(), Error<<WH as ErrorType>::Error>> {
        close_channel_via(&self.shared, ch).await
    }

    fn channel_ids(&self, ch: ChannelId) -> Result<ChannelIds, Error<<WH as ErrorType>::Error>> {
        let chs = self.shared.lock_channels();
        channel_ids_of(&chs, ch)
    }

    async fn acquire_credit(
        &self,
        ch: ChannelId,
        want: usize,
    ) -> Result<usize, Error<<WH as ErrorType>::Error>> {
        let Some(signal) = self.shared.signals.get(ch.slot) else {
            return Err(Error::ChannelClosed);
        };

        // Take a place in the send queue. Only its head may reserve, so
        // concurrent writers are served in arrival order: a writer that
        // loops straight back after sending queues behind the ones
        // already waiting and cannot drain a grant past them.
        let place = {
            let mut chs = self.shared.lock_channels();
            let Some(slot) = slot_for_mut(&mut chs, ch) else {
                return Err(Error::ChannelClosed);
            };
            if slot.is_closed() {
                return Err(slot.closed_error());
            }
            slot.send_queue().enqueue()
        };
        let mut queue = QueueGuard {
            shared: &self.shared,
            ch,
            place,
            served: false,
        };

        loop {
            let listener = signal.listen();
            match self.try_reserve(ch, want, place) {
                Some(Ok((n, more))) => {
                    queue.served = true;
                    // Budget survived the reservation: prompt the next
                    // writer in line to take its share.
                    if more {
                        signal.wake();
                    }
                    return Ok(n);
                }
                Some(Err(e)) => return Err(e),
                None => {
                    self.shared.check_live()?;
                    listener.await;
                }
            }
        }
    }

    /// Reserve send credit if it is `place`'s turn and budget allows.
    #[allow(clippy::type_complexity)]
    fn try_reserve(
        &self,
        ch: ChannelId,
        want: usize,
        place: u64,
    ) -> Option<Result<(usize, bool), Error<<WH as ErrorType>::Error>>> {
        let mut chs = self.shared.lock_channels();
        let Some(slot) = slot_for_mut(&mut chs, ch) else {
            return Some(Err(Error::ChannelClosed));
        };
        if slot.is_closed() {
            return Some(Err(slot.closed_error()));
        }
        if slot.send_queue().turn() != place {
            return None;
        }
        slot.try_reserve_send(want).map(|n| {
            slot.send_queue().advance();
            Ok((n, slot.budget().is_some()))
        })
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
    shared: Arc<Shared<WH>>,
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
            self.shared.desync.check()?;
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

/// Send CLSE for `ch` and free its slot: the close path shared by
/// [`Writer::close_channel`] and [`Reader::close_channel`].
async fn close_channel_via<WH>(
    shared: &Shared<WH>,
    ch: ChannelId,
) -> Result<(), Error<<WH as ErrorType>::Error>>
where
    WH: Write,
{
    shared.desync.check()?;
    let ids = {
        let chs = shared.lock_channels();
        channel_ids_of(&chs, ch)?
    };
    {
        let mut wh = shared.lock_write().await?;
        send_pkt(
            &mut *wh,
            &shared.desync,
            &Packet::close(ids),
            shared.negotiated.checksum(),
        )
        .await?;
    }
    {
        let mut chs = shared.lock_channels();
        if slot_for(&chs, ch).is_some() {
            chs[ch.slot] = None;
        }
    }
    if let Some(signal) = shared.signals.get(ch.slot) {
        signal.wake();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::channel::AckDecision;
    use crate::base::connection::{Connection, ConnectionConfig, HostBanner};
    use crate::base::mock::{
        abandon, now, okay, split_with_channel, withdraw, Mock, NoAuth, SharedMock,
    };

    /// Stage one OPEN out of the queue, then deliver more packets —
    /// the device-side traffic a staged request can race against.
    fn staged_with_followup(
        followup: &[Packet],
    ) -> (
        Reader<SharedMock, SharedMock>,
        SplitIncoming<SharedMock>,
        SharedMock,
    ) {
        use core::future::Future as _;
        use core::task::{Context, Poll, Waker};

        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, _writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();

        seen.feed(&Packet::new(Command::Open, 80, 0, b"tcp:80\0".to_vec()));
        let pump = |reader: &mut Reader<SharedMock, SharedMock>| {
            let mut buf = [0u8; 16];
            let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
            let mut cx = Context::from_waker(Waker::noop());
            // Everything fed so far is dispatched on the way; the
            // drained mock then reports EOF, which is how the pump
            // knows the read went all the way through.
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(Err(Error::UnexpectedEof)) => {}
                other => panic!("expected the drained-transport EOF, got {other:?}"),
            }
        };
        pump(&mut reader);
        let inc = reader.try_accept_incoming().expect("the OPEN was queued");

        for pkt in followup {
            seen.feed(pkt);
        }
        pump(&mut reader);
        (reader, inc, seen)
    }

    #[test]
    fn a_device_cancel_reaches_the_staged_request() {
        let (mut reader, inc, seen) = staged_with_followup(&[withdraw(80)]);

        // The verdict observes the withdrawal: no READY, no channel.
        let err = now(inc.accept()).unwrap_err();
        assert!(
            matches!(err, Error::ChannelClosed),
            "expected ChannelClosed, got {err:?}"
        );
        assert!(
            !seen
                .sent()
                .iter()
                .any(|(cmd, _, arg1, _)| *cmd == Command::Ready && *arg1 == 80),
            "READY must not answer a withdrawn OPEN"
        );
        // The dead request does not come back to the queue either.
        assert!(reader.try_accept_incoming().is_none());
    }

    #[test]
    fn a_staged_reject_after_the_cancel_stays_silent() {
        let (_reader, inc, seen) = staged_with_followup(&[withdraw(80)]);

        now(inc.reject()).unwrap();
        assert!(
            !seen
                .sent()
                .iter()
                .any(|(cmd, _, arg1, _)| *cmd == Command::Close && *arg1 == 80),
            "a withdrawn OPEN expects no answer"
        );
    }

    #[test]
    fn a_withdrawal_racing_the_accept_closes_the_split_slot() {
        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn());
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, _writer) = conn.split().unwrap();

        seen.feed(&Packet::new(Command::Open, 90, 0, b"tcp:90\0".to_vec()));
        let inc = now(reader.accept_incoming()).unwrap();
        let ch = now(inc.accept()).unwrap();

        // The withdrawal crossed our READY: a reader parked on the
        // channel must observe the close, not wait forever.
        seen.feed(&withdraw(90));
        let mut buf = [0u8; 8];
        let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
        assert!(
            matches!(err, Error::ChannelClosed),
            "expected ChannelClosed, got {err:?}"
        );
    }

    #[test]
    fn held_holders_spend_the_open_storm_budget() {
        use core::future::Future as _;
        use core::task::{Context, Poll, Waker};

        let open_pkt =
            |remote_id: u32, dest: &[u8]| Packet::new(Command::Open, remote_id, 0, dest.to_vec());

        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(2),
        ))
        .unwrap();
        let (mut reader, _writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();

        let pump = |reader: &mut Reader<SharedMock, SharedMock>| {
            let mut buf = [0u8; 16];
            let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
            let mut cx = Context::from_waker(Waker::noop());
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(Err(Error::UnexpectedEof)) => {}
                other => panic!("expected the drained-transport EOF, got {other:?}"),
            }
        };

        // Two held holders exhaust the two-channel budget without ever
        // touching the queue length.
        seen.feed(&open_pkt(60, b"tcp:60\0"));
        pump(&mut reader);
        let held_a = reader.try_accept_incoming().unwrap();
        seen.feed(&open_pkt(61, b"tcp:61\0"));
        pump(&mut reader);
        let held_b = reader.try_accept_incoming().unwrap();
        assert_eq!(reader.shared.lock_incoming().len(), 0);

        // The third OPEN must be refused on arrival: an application
        // sitting on holders cannot make the bound unenforceable.
        seen.feed(&open_pkt(62, b"tcp:62\0"));
        pump(&mut reader);
        assert!(
            seen.sent()
                .iter()
                .any(|(cmd, _, arg1, _)| *cmd == Command::Close && *arg1 == 62),
            "the OPEN past the budget must be refused with CLSE"
        );
        assert!(
            reader.try_accept_incoming().is_none(),
            "nothing may be queued past the budget"
        );

        // The budget comes back with the holders.
        drop(held_a);
        drop(held_b);
        assert_eq!(reader.shared.lock_incoming().len(), 2);
    }

    #[test]
    fn repeated_refusal_cancellation_cannot_grow_the_queue() {
        use core::future::Future as _;
        use core::task::{Context, Poll, Waker};

        let open_pkt =
            |remote_id: u32, dest: &[u8]| Packet::new(Command::Open, remote_id, 0, dest.to_vec());

        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(2),
        ))
        .unwrap();
        let (mut reader, _writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        for id in [70, 71, 72] {
            let dest = alloc::format!("tcp:{id}\0");
            seen.feed(&open_pkt(id, dest.as_bytes()));
        }

        let shared = Arc::clone(&reader.shared);
        let wh = now(shared.write_half.lock());
        let cancel_once = |reader: &mut Reader<SharedMock, SharedMock>| {
            let mut buf = [0u8; 16];
            let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        };
        // First cancellation leaves the leftover 72: cap + 1.
        cancel_once(&mut reader);
        assert_eq!(reader.shared.lock_incoming().len(), 3);

        // With a new OPEN waiting on the wire, every further cancelled
        // read parks on re-refusing the leftover and takes nothing in:
        // the queue must not grow past cap + 1.
        seen.feed(&open_pkt(73, b"tcp:73\0"));
        for _ in 0..3 {
            cancel_once(&mut reader);
            assert_eq!(
                reader.shared.lock_incoming().len(),
                3,
                "a repeated cancellation grew the supposedly bounded queue"
            );
        }

        // Once a read is allowed to finish, the leftover is refused
        // first, only then is the new OPEN taken in — and refused too,
        // over the cap as it is.
        drop(wh);
        {
            let mut buf = [0u8; 16];
            let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
            let mut cx = Context::from_waker(Waker::noop());
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(Err(Error::UnexpectedEof)) => {}
                other => panic!("expected the drained-transport EOF, got {other:?}"),
            }
        }
        let refused: alloc::vec::Vec<u32> = seen
            .sent()
            .iter()
            .filter(|(cmd, ..)| *cmd == Command::Close)
            .map(|&(_, _, arg1, _)| arg1)
            .collect();
        assert_eq!(refused, [72, 73], "leftover first, then the new arrival");
        let q = reader.shared.lock_incoming();
        assert_eq!(q.len(), 2, "back at the cap");
        assert_eq!(q.front().unwrap().remote, RemoteId::from(70));
    }

    #[test]
    fn a_cancelled_overflow_refusal_keeps_the_open_recoverable() {
        use core::future::Future as _;
        use core::task::{Context, Poll, Waker};

        let open_pkt =
            |remote_id: u32, dest: &[u8]| Packet::new(Command::Open, remote_id, 0, dest.to_vec());

        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
        let seen = SharedMock::new(mock);
        // Two incoming slots: OPENs 70 and 71 fill the queue, 72
        // overflows it and has to be refused with CLSE.
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new().with_max_channels(2),
        ))
        .unwrap();
        let (mut reader, _writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        for id in [70, 71, 72] {
            let dest = alloc::format!("tcp:{id}\0");
            seen.feed(&open_pkt(id, dest.as_bytes()));
        }

        // Hold the write lock, so the refusal's CLSE cannot start —
        // the exact window a cancel lands in.
        let shared = Arc::clone(&reader.shared);
        let wh = now(shared.write_half.lock());
        {
            let mut buf = [0u8; 16];
            let mut fut = core::pin::pin!(reader.read_channel(ch, &mut buf));
            let mut cx = Context::from_waker(Waker::noop());
            // The poll queues 70 and 71, then parks refusing 72.
            assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
            // Drop mid-refusal — cancellation.
        }
        drop(wh);

        // The refused OPEN survived the cancel: it is back at the head
        // of the queue (one past the cap), and the connection is still
        // healthy — nothing was half-written.
        {
            let q = reader.shared.lock_incoming();
            assert_eq!(q.len(), 3, "the refused OPEN must be requeued");
            assert_eq!(q.front().unwrap().remote, RemoteId::from(72));
        }
        reader
            .shared
            .desync
            .check::<core::convert::Infallible>()
            .expect("a cancelled refusal must not poison the connection");

        // The verdict machinery now answers it: adbd gets its CLSE.
        let inc = reader.try_accept_incoming().unwrap();
        assert_eq!(inc.destination(), b"tcp:72\0");
        now(inc.reject()).unwrap();
        let (cmd, _, arg1, _) = seen.sent().last().unwrap().clone();
        assert_eq!(
            (cmd, arg1),
            (Command::Close, 72),
            "the CLSE names the refused OPEN"
        );
    }

    #[test]
    fn a_cancelled_write_stops_both_halves() {
        // Index 1: the header is out, the payload write hangs.
        let (mut reader, writer, ch) = split_with_channel(Some(1));
        abandon(writer.write_channel(ch, b"payload-that-never-made-it"));

        let err = now(writer.write_channel(ch, b"more")).unwrap_err();
        assert!(
            matches!(err, Error::Desynchronized),
            "writer: expected Desynchronized, got {err:?}"
        );

        let mut buf = [0u8; 16];
        let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
        assert!(
            matches!(err, Error::Desynchronized),
            "reader: expected Desynchronized, got {err:?}"
        );
    }

    #[test]
    fn a_cancelled_write_wakes_reads_waiting_on_other_channels() {
        use alloc::task::Wake;
        use core::task::{Context, Waker};

        struct Woken(AtomicBool);
        impl Wake for Woken {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        // Two channels; the write on `a` hangs after its header (the
        // handshake and both OPENs take the first six writes).
        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn())
            .feed(&okay(1))
            .feed(&okay(2))
            .stall_write(6 + 1);
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let a = now(reader.open_channel(b"shell:\0")).unwrap();
        let b = now(reader.open_channel(b"shell:\0")).unwrap();

        let woken = Arc::new(Woken(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&woken));
        let mut buf = [0u8; 16];
        let mut read = pin!(writer.read_channel(b, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());

        abandon(writer.write_channel(a, b"payload-that-never-made-it"));
        assert!(
            woken.0.load(Ordering::Relaxed),
            "the read on b slept through the desync"
        );
        let err = now(read).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
    }

    #[test]
    fn a_ready_without_credit_fails_a_writer_open_on_a_reader_driven_connection() {
        use crate::base::error::ProtocolError;
        use core::task::{Context, Waker};

        // Queued behind the first channel's grant: the device's answer
        // to the Writer's OPEN (local id 2), without its credit.
        let (mut reader, writer, ch, seen) = crate::base::mock::split_one_channel_delayed_ack(
            64,
            &[Packet::new(Command::Ready, 43, 2, Vec::new())],
        );
        let mut open = pin!(writer.open_channel(b"svc:\0"));
        assert!(open
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());

        // The reader-driven call that happens to read the READY gets
        // the fault, as such calls do ...
        let mut buf = [0u8; 8];
        let err = now(reader.read_channel(ch, &mut buf)).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
            "reader: got {err:?}"
        );
        // ... and the opener hears of it too, instead of waiting on.
        let err = now(open).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::ShortReadyPayload)),
            "opener: got {err:?}"
        );
        let (cmd, arg0, arg1, _) = seen.sent().last().unwrap().clone();
        assert_eq!((cmd, arg0, arg1), (Command::Close, 2, 43));
    }

    #[test]
    fn a_read_dropped_waiting_for_the_ack_lock_takes_nothing() {
        use core::task::{Context, Waker};

        let (_reader, writer, ch, _seen) =
            crate::base::mock::split_one_channel_delayed_ack(64, &[]);
        // Five bytes dispatched and not yet acknowledged, as `run`
        // leaves them under delayed ACK.
        {
            let mut chs = writer.shared.lock_channels();
            let slot = slot_for_mut(&mut chs, ch).unwrap();
            assert!(matches!(slot.apply_write(b"hello"), Ok(AckDecision::Hold)));
        }
        // Another task is mid-packet, so the read's OKAY has to wait.
        let wh = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 8];
        {
            let mut read = pin!(writer.read_channel(ch, &mut buf));
            assert!(read
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        {
            let chs = writer.shared.lock_channels();
            let slot = chs[ch.slot].as_ref().unwrap();
            assert_eq!(
                (slot.buffered(), slot.unacked()),
                (5, 5),
                "a read dropped while waiting took the bytes"
            );
        }
        drop(wh);
        let n = now(writer.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn an_opener_dropped_after_its_ready_was_taken_still_closes_the_channel() {
        use core::task::{Context, Waker};

        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn())
            .feed(&okay(1))
            // The device accepts the Writer's OPEN (local id 2), then
            // writes on the first channel.
            .feed(&Packet::new(Command::Ready, 43, 2, Vec::new()))
            .feed(&Packet::new(Command::Write, 42, 1, b"x".to_vec()));
        let seen = SharedMock::new(mock);
        let conn = now(Connection::connect(
            seen.clone(),
            NoAuth,
            HostBanner::Features(&[]),
            ConnectionConfig::new(),
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        {
            let mut open = pin!(writer.open_channel(b"svc:\0"));
            assert!(open
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            // Another call takes the READY; the opener never looks again.
            let mut buf = [0u8; 4];
            assert_eq!(now(reader.read_channel(ch, &mut buf)).unwrap(), 1);
        }

        // The next packet anyone writes goes out behind the owed CLSE.
        now(writer.write_channel(ch, b"y")).unwrap();
        let sent = seen.sent();
        let tail: Vec<_> = sent[sent.len() - 2..]
            .iter()
            .map(|(cmd, arg0, arg1, _)| (*cmd, *arg0, *arg1))
            .collect();
        assert_eq!(tail, [(Command::Close, 2, 43), (Command::Write, 1, 42)]);
    }

    #[test]
    fn a_fault_closes_the_device_end_even_once_the_slot_is_gone() {
        // The opener was given up on between the fault and this: its
        // slot is free, but the device still holds the channel open.
        let (reader, _writer, _ch) = split_with_channel(None);
        let seen = reader.shared.write_half.try_lock().unwrap().clone();
        let ids = ChannelIds {
            local: LocalId::from(99),
            remote: RemoteId::from(77),
        };
        now(reader.shared.fail_channel(5, ids, ChannelFault::RxOverflow)).unwrap();
        let (cmd, arg0, arg1, _) = seen.sent().last().unwrap().clone();
        assert_eq!((cmd, arg0, arg1), (Command::Close, 99, 77));
    }

    #[test]
    fn a_read_that_owes_no_ack_does_not_wait_for_the_write_lock() {
        // Without delayed ACK, a 1 KiB watermark.
        let config = ConnectionConfig::new()
            .with_max_payload(1024)
            .with_initial_ack_bytes(1024);
        let mut mock = Mock::new();
        mock.feed(&crate::base::mock::cnxn()).feed(&okay(1));
        let conn = now(Connection::connect(
            SharedMock::new(mock),
            NoAuth,
            HostBanner::Features(&[]),
            config,
        ))
        .unwrap();
        let (mut reader, writer) = conn.split().unwrap();
        let ch = now(reader.open_channel(b"shell:\0")).unwrap();
        // Well past the watermark, with its acknowledgement held back.
        {
            let mut chs = writer.shared.lock_channels();
            let slot = slot_for_mut(&mut chs, ch).unwrap();
            // The first is acknowledged on arrival, the second takes the
            // channel past the watermark and is held.
            slot.apply_write(&[0xEE; 1000]).unwrap();
            slot.apply_write(&[0xEE; 1000]).unwrap();
        }

        // Another task holds the write half; a small read leaves the
        // buffer past the watermark, so it owes nothing and goes ahead.
        let _wh = now(writer.shared.write_half.lock());
        let mut buf = [0u8; 8];
        assert_eq!(now(writer.read_channel(ch, &mut buf)).unwrap(), 8);
        let chs = writer.shared.lock_channels();
        assert_eq!(chs[ch.slot].as_ref().unwrap().unacked(), 1000);
    }

    #[test]
    fn a_read_woken_on_a_desynchronized_connection_hands_out_nothing() {
        use core::task::{Context, Waker};

        // Index 1: the header is out, the payload write hangs.
        let (_reader, writer, ch) = split_with_channel(Some(1));
        let mut buf = [0u8; 8];
        let mut read = pin!(writer.read_channel(ch, &mut buf));
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());

        // Data lands while another task abandons a packet mid-write.
        {
            let mut chs = writer.shared.lock_channels();
            let slot = slot_for_mut(&mut chs, ch).unwrap();
            slot.apply_write(b"hi").unwrap();
        }
        abandon(writer.write_channel(ch, b"payload-that-never-made-it"));

        let err = now(read).unwrap_err();
        assert!(matches!(err, Error::Desynchronized), "got {err:?}");
    }

    #[test]
    fn writes_that_complete_leave_both_halves_working() {
        let (mut reader, writer, ch) = split_with_channel(None);
        now(writer.write_channel(ch, b"payload")).unwrap();
        let mut buf = [0u8; 16];
        // Nothing left to read, but the call is refused for that reason
        // rather than for a broken stream.
        assert!(!matches!(
            now(reader.read_channel(ch, &mut buf)),
            Err(Error::Desynchronized)
        ));
    }
}

#[cfg(test)]
mod send_queue_tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};

    use crate::base::channel::{slot_for_mut, ChannelId};
    use crate::base::mock::{okay_with_budget, split_one_channel_delayed_ack, SharedMock};
    use crate::base::protocol::command::Command;

    fn poll_once<F: Future + ?Sized>(fut: Pin<&mut F>) -> Poll<F::Output> {
        let mut cx = Context::from_waker(Waker::noop());
        fut.poll(&mut cx)
    }

    /// WRTE payloads the writer put on the wire, in order.
    fn wrte_payloads(seen: &SharedMock) -> Vec<Vec<u8>> {
        seen.sent()
            .into_iter()
            .filter(|(cmd, ..)| *cmd == Command::Write)
            .map(|(_, _, _, payload)| payload)
            .collect()
    }

    /// Feed `credit` bytes of delayed-ack budget straight into the
    /// slot and wake the queue — standing in for a device OKAY, so a
    /// test can dose grants between polls.
    fn grant(writer: &super::Writer<SharedMock>, ch: ChannelId, credit: u32) {
        {
            let mut chs = writer.shared.lock_channels();
            slot_for_mut(&mut chs, ch)
                .unwrap()
                .apply_ready(&credit.to_le_bytes())
                .unwrap();
        }
        writer.shared.signals[ch.slot].wake();
    }

    #[test]
    fn a_returning_writer_queues_behind_the_one_already_waiting() {
        // Zero initial credit parks both writers, in arrival order,
        // before any budget exists.
        let (_reader, writer, ch, seen) = split_one_channel_delayed_ack(0, &[]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaaaaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        // A grant covering one chunk: the head sends `aaaaa` and
        // requeues for its remainder — behind the writer that was
        // already waiting.
        grant(&writer, ch, 5);
        assert!(poll_once(first.as_mut()).is_pending());

        // The shared grant arrives. Polling the returning writer first
        // must not let it drain the budget past the queue.
        grant(&writer, ch, 100);
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_ready());
        assert!(poll_once(first.as_mut()).is_ready());

        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 3, "expected three WRTEs, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"aaaaa");
        assert_eq!(
            &wrtes[1], b"bbbbb",
            "the queued writer goes before the returning one"
        );
        assert_eq!(&wrtes[2], b"aaaaa");
    }

    #[test]
    fn a_grant_is_served_in_arrival_order_not_by_the_scheduler() {
        // A budget of 5 lets the first writer send one chunk and queue
        // again behind the second; the grant that follows covers both.
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(5, &[okay_with_budget(1, 100)]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaaaaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        // The reader dispatches the grant that covers everyone...
        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(reader.read_channel(ch, &mut buf));
            let _ = poll_once(read.as_mut());
        }

        // ...and polling the second writer first must not let it cut
        // into the frame the first one is still sending.
        assert!(poll_once(second.as_mut()).is_pending());
        assert!(poll_once(first.as_mut()).is_ready());
        assert!(poll_once(second.as_mut()).is_ready());

        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 3, "expected three WRTEs, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"aaaaa");
        assert_eq!(&wrtes[1], b"aaaaa");
        assert_eq!(&wrtes[2], b"bbbbb");
    }

    #[test]
    fn a_cancelled_head_hands_its_turn_to_the_next_writer() {
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(0, &[okay_with_budget(1, 50)]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());

        // Dropped before it ever sent a byte: the head of the queue
        // leaves, and the turn has to pass on.
        drop(first);

        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(reader.read_channel(ch, &mut buf));
            let _ = poll_once(read.as_mut());
        }

        assert!(poll_once(second.as_mut()).is_ready());
        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 1, "expected one WRTE, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"bbbbb");
    }

    #[test]
    fn a_cancelled_place_mid_queue_is_skipped_when_reached() {
        let (mut reader, writer, ch, seen) =
            split_one_channel_delayed_ack(0, &[okay_with_budget(1, 50)]);

        let mut first = Box::pin(writer.write_channel(ch, b"aaaaa"));
        let mut second = Box::pin(writer.write_channel(ch, b"bbbbb"));
        let mut third = Box::pin(writer.write_channel(ch, b"ccccc"));
        assert!(poll_once(first.as_mut()).is_pending());
        assert!(poll_once(second.as_mut()).is_pending());
        assert!(poll_once(third.as_mut()).is_pending());

        // A hole in the middle of the queue, not at its head.
        drop(second);

        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(reader.read_channel(ch, &mut buf));
            let _ = poll_once(read.as_mut());
        }

        assert!(poll_once(first.as_mut()).is_ready());
        assert!(poll_once(third.as_mut()).is_ready());

        let wrtes = wrte_payloads(&seen);
        assert_eq!(wrtes.len(), 2, "expected two WRTEs, got {wrtes:?}");
        assert_eq!(&wrtes[0], b"aaaaa");
        assert_eq!(&wrtes[1], b"ccccc");
    }
}

#[cfg(test)]
mod incoming_tests {
    use crate::base::channel::ChannelId;
    use crate::base::mock::{now, split_one_channel_delayed_ack, wrte};
    use crate::base::protocol::command::Command;
    use crate::base::protocol::Packet;

    fn open_pkt(remote_id: u32, credit: u32, dest: &[u8]) -> Packet {
        Packet::new(Command::Open, remote_id, credit, dest.to_vec())
    }

    #[test]
    fn a_device_open_on_a_split_reader_is_accepted_and_serves_data() {
        let (mut reader, writer, _ch, seen) = split_one_channel_delayed_ack(0, &[]);
        seen.feed(&open_pkt(77, 4096, b"tcp:9090\0"));

        let incoming = now(reader.accept_incoming()).unwrap();
        assert_eq!(incoming.destination(), b"tcp:9090\0");
        let ch: ChannelId = now(incoming.accept()).unwrap();

        let (cmd, local, remote, payload) = seen.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Ready);
        assert_eq!(remote, 77);
        assert_eq!(payload.len(), 4);

        // Their data arrives on the accepted channel, and our write
        // spends the OPEN-granted budget through the split writer.
        seen.feed(&wrte(local, b"ping"));
        let mut buf = [0u8; 16];
        let n = now(reader.read_channel(ch, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"ping");

        now(writer.write_channel(ch, b"pong")).unwrap();
        let (cmd, l, r, payload) = seen.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Write);
        assert_eq!((l, r), (local, 77));
        assert_eq!(payload, b"pong");
    }

    #[test]
    fn a_rejected_open_on_a_split_reader_answers_clse() {
        let (mut reader, _writer, _ch, seen) = split_one_channel_delayed_ack(0, &[]);
        seen.feed(&open_pkt(88, 0, b"tcp:1\0"));

        let incoming = now(reader.accept_incoming()).unwrap();
        now(incoming.reject()).unwrap();

        let (cmd, local, remote, _) = seen.sent().last().unwrap().clone();
        assert_eq!(cmd, Command::Close);
        assert_eq!((local, remote), (0, 88));
    }
}

#[cfg(test)]
mod backpressure_tests {
    use crate::base::mock::{now, split_two_channels_delayed_ack, wrte};

    #[test]
    fn a_split_reader_returns_credit_only_for_what_was_read() {
        let (mut reader, a, b, seen) =
            split_two_channels_delayed_ack(&[wrte(2, b"for-b"), wrte(1, b"for-a")]);

        let mut buf = [0u8; 32];
        now(reader.read_channel(a, &mut buf)).unwrap();
        assert!(
            seen.acks_for(2).is_empty(),
            "channel B was buffered, not read: its credit stays with us"
        );

        let n = now(reader.read_channel(b, &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"for-b");
        assert_eq!(seen.acks_for(2), alloc::vec![5]);
    }
}
