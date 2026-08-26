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
use core::sync::atomic::{AtomicU32, Ordering};
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use event_listener::{Event, EventListener};
use std::sync::Mutex;

use alloc::collections::VecDeque;

use crate::base::channel::{
    channel_ids_of, dispatch_packet, slot_for_mut, ChannelId, ChannelSlot, ChannelState,
    DispatchOutcome, PendingOpen,
};
use crate::base::connection::{
    ConnectionConfig, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_FEATURES, DEFAULT_MAX_PROPERTIES,
};
use crate::base::error::Error;
use crate::base::protocol::command::Command;
use crate::base::protocol::Checksum;
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

pub(crate) struct Shared<WH, const MC: usize, const MP: usize, const MF: usize> {
    pub(crate) write_half: AsyncMutex<WH>,
    pub(crate) channels: Mutex<[Option<ChannelSlot>; MC]>,
    pub(crate) signals: [FlowSignal; MC],
    pub(crate) max_payload: u32,
    pub(crate) protocol_version: u32,
    pub(crate) config: ConnectionConfig,
    pub(crate) delayed_ack: bool,
    pub(crate) device_banner: Option<DeviceBanner<MP, MF>>,
    pub(crate) local_id_counter: AtomicU32,
    pub(crate) desync: DesyncFlag,
    /// Device-initiated OPENs awaiting [`Reader::accept_incoming`].
    pub(crate) incoming: Mutex<VecDeque<PendingOpen>>,
}

impl<WH, const MC: usize, const MP: usize, const MF: usize> Shared<WH, MC, MP, MF> {
    fn next_local_id(&self) -> u32 {
        loop {
            let id = self.local_id_counter.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    fn lock_channels(&self) -> std::sync::MutexGuard<'_, [Option<ChannelSlot>; MC]> {
        self.channels.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_incoming(&self) -> std::sync::MutexGuard<'_, VecDeque<PendingOpen>> {
        self.incoming.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn checksum(&self) -> Checksum {
        Checksum::for_version(self.protocol_version)
    }
}

struct SlotGuard<WH, const MC: usize, const MP: usize, const MF: usize> {
    shared: Arc<Shared<WH, MC, MP, MF>>,
    idx: usize,
    armed: bool,
}

impl<WH, const MC: usize, const MP: usize, const MF: usize> SlotGuard<WH, MC, MP, MF> {
    fn new(shared: Arc<Shared<WH, MC, MP, MF>>, idx: usize) -> Self {
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

impl<WH, const MC: usize, const MP: usize, const MF: usize> Drop for SlotGuard<WH, MC, MP, MF> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut chs = self.shared.lock_channels();
        if self.idx < chs.len() {
            chs[self.idx] = None;
        }
    }
}

struct CreditGuard<'a, WH, const MC: usize, const MP: usize, const MF: usize> {
    shared: &'a Shared<WH, MC, MP, MF>,
    ch: ChannelId,
    n: usize,
    committed: bool,
}

impl<'a, WH, const MC: usize, const MP: usize, const MF: usize> CreditGuard<'a, WH, MC, MP, MF> {
    fn new(shared: &'a Shared<WH, MC, MP, MF>, ch: ChannelId, n: usize) -> Self {
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

impl<WH, const MC: usize, const MP: usize, const MF: usize> Drop
    for CreditGuard<'_, WH, MC, MP, MF>
{
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        {
            let mut chs = self.shared.lock_channels();
            if let Some(slot) = slot_for_mut(&mut *chs, self.ch) {
                slot.refund(self.n, self.shared.delayed_ack);
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
struct QueueGuard<'a, WH, const MC: usize, const MP: usize, const MF: usize> {
    shared: &'a Shared<WH, MC, MP, MF>,
    ch: ChannelId,
    place: u64,
    served: bool,
}

impl<WH, const MC: usize, const MP: usize, const MF: usize> Drop
    for QueueGuard<'_, WH, MC, MP, MF>
{
    fn drop(&mut self) {
        if self.served {
            return;
        }
        let head_moved = {
            let mut chs = self.shared.lock_channels();
            match slot_for_mut(&mut *chs, self.ch) {
                Some(slot) => slot.send_leave(self.place),
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

/// Read half of a split [`Connection`](crate::Connection).
///
/// Drives packet reception, dispatching OKAY/CLSE/WRTE packets for all
/// channels. Only one Reader exists per connection.
pub struct Reader<
    RH,
    WH,
    const MAX_CHANNELS: usize = DEFAULT_MAX_CHANNELS,
    const MAX_PROPERTIES: usize = DEFAULT_MAX_PROPERTIES,
    const MAX_FEATURES: usize = DEFAULT_MAX_FEATURES,
> where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    read_half: RH,
    recv_buf: BytesMut,
    shared: Arc<Shared<WH, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>>,
}

impl<RH, WH, const MC: usize, const MP: usize, const MF: usize> Reader<RH, WH, MC, MP, MF>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    pub(crate) fn new(
        read_half: RH,
        recv_buf: BytesMut,
        shared: Arc<Shared<WH, MC, MP, MF>>,
    ) -> Self {
        Self {
            read_half,
            recv_buf,
            shared,
        }
    }

    /// Maximum payload size for outbound packets.
    pub fn max_payload(&self) -> u32 {
        self.shared.max_payload
    }

    /// Resource limits this connection was opened with.
    pub fn config(&self) -> &ConnectionConfig {
        &self.shared.config
    }

    /// Protocol version in effect: `min(ADB_VERSION, device version)`.
    pub fn protocol_version(&self) -> u32 {
        self.shared.protocol_version
    }

    /// Whether delayed-ACK flow control was negotiated.
    pub fn delayed_ack(&self) -> bool {
        self.shared.delayed_ack
    }

    /// Raw device banner bytes from the CNXN handshake.
    pub fn device_banner(&self) -> Option<&[u8]> {
        self.shared.device_banner.as_ref().map(|b| b.raw())
    }

    /// Parsed device banner from the CNXN handshake.
    pub fn device_banner_parsed(&self) -> Option<&DeviceBanner<MP, MF>> {
        self.shared.device_banner.as_ref()
    }

    /// Fail with [`Error::MissingFeature`] if the device banner was
    /// parsed and does not list `feature`. Permissive when no banner
    /// is available.
    pub fn require_feature(
        &self,
        feature: crate::protocol::features::Feature,
    ) -> Result<(), Error<<RH as ErrorType>::Error>> {
        match &self.shared.device_banner {
            Some(b) if b.has_feature(&feature) => Ok(()),
            Some(_) => Err(Error::MissingFeature(feature)),
            None => Ok(()),
        }
    }

    /// Open a channel to `destination`.
    ///
    /// Sends OPEN and waits for the matching OKAY (while dispatching any
    /// unrelated packets that arrive in the meantime).
    ///
    /// **Not cancellation-safe.** Dropping the future after the OPEN
    /// packet has been sent leaves the device-side channel half-open
    /// until the connection is closed — async Drop cannot send the
    /// matching CLSE. If the call returns `Err`, a best-effort CLSE is
    /// sent before the error propagates.
    pub async fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<<RH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        let (slot_idx, local_id) = {
            let mut chs = self.shared.lock_channels();
            let idx = chs
                .iter()
                .position(|s| s.is_none())
                .ok_or(Error::NoFreeChannels)?;
            let id = self.shared.next_local_id();
            chs[idx] = Some(ChannelSlot::new(id));
            (idx, id)
        };
        let mut guard = SlotGuard::new(Arc::clone(&self.shared), slot_idx);

        let open_arg1 = if self.shared.delayed_ack {
            self.shared.config.advertised_ack_bytes()
        } else {
            0
        };
        let pkt = Packet::new(Command::Open, local_id, open_arg1, destination.to_vec());
        {
            let mut wh = self.shared.write_half.lock().await;
            send_pkt(&mut *wh, &self.shared.desync, &pkt, self.shared.checksum()).await?;
        }

        let result = self.await_open_ack(local_id, slot_idx, &mut guard).await;
        if let Err(ref e) = result {
            if !matches!(e, Error::ChannelClosed) {
                let mut wh = self.shared.write_half.lock().await;
                let _ = send_raw(
                    &mut *wh,
                    &self.shared.desync,
                    Command::Close,
                    local_id,
                    0,
                    &[],
                    self.shared.checksum(),
                )
                .await;
            }
        }
        result
    }

    async fn await_open_ack(
        &mut self,
        local_id: u32,
        slot_idx: usize,
        guard: &mut SlotGuard<WH, MC, MP, MF>,
    ) -> Result<ChannelId, Error<<RH as ErrorType>::Error>> {
        loop {
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Ready if pkt.arg1 == local_id => {
                    {
                        let mut chs = self.shared.lock_channels();
                        if let Some(slot) = chs[slot_idx].as_mut() {
                            slot.accept_open_ready(pkt.arg0, &pkt.data, self.shared.delayed_ack)?;
                        }
                    }
                    guard.disarm();
                    return Ok(ChannelId {
                        slot: slot_idx,
                        local_id,
                    });
                }
                Command::Close if pkt.arg1 == local_id => {
                    return Err(Error::ChannelClosed);
                }
                _ => self.dispatch(pkt).await?,
            }
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
        let delayed_ack = self.shared.delayed_ack;
        let watermark = self.shared.config.rx_watermark();
        let buffered = {
            let mut chs = self.shared.lock_channels();
            let slot = slot_for_mut(&mut *chs, ch).ok_or(Error::ChannelClosed)?;
            if !slot.rx_buf.is_empty() {
                let n = buf.len().min(slot.rx_buf.len());
                buf[..n].copy_from_slice(&slot.rx_buf[..n]);
                let _ = slot.rx_buf.split_to(n);
                Some((n, slot.consume(n, delayed_ack, watermark)))
            } else if slot.is_closed() {
                return Err(Error::ChannelClosed);
            } else {
                None
            }
        };
        if let Some((n, ack)) = buffered {
            if let Some((local_id, remote_id, len)) = ack {
                let mut wh = self.shared.write_half.lock().await;
                send_okay_to(
                    &mut *wh,
                    &self.shared.desync,
                    delayed_ack,
                    local_id,
                    remote_id,
                    len,
                    self.shared.checksum(),
                )
                .await?;
            }
            return Ok(n);
        }

        let (local_id, _) = self.channel_ids(ch)?;

        loop {
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Write if pkt.arg1 == local_id => {
                    let n = buf.len().min(pkt.data.len());
                    buf[..n].copy_from_slice(&pkt.data[..n]);
                    let ack = {
                        let mut chs = self.shared.lock_channels();
                        match slot_for_mut(&mut *chs, ch) {
                            Some(slot) => slot.deliver(
                                &pkt.data,
                                n,
                                self.shared.config.rx_cap(),
                                delayed_ack,
                                watermark,
                            )?,
                            None => None,
                        }
                    };
                    if let Some((local_id, remote_id, len)) = ack {
                        let mut wh = self.shared.write_half.lock().await;
                        send_okay_to(
                            &mut *wh,
                            &self.shared.desync,
                            delayed_ack,
                            local_id,
                            remote_id,
                            len,
                            self.shared.checksum(),
                        )
                        .await?;
                    }
                    return Ok(n);
                }
                Command::Close if pkt.arg1 == local_id => {
                    {
                        let mut chs = self.shared.lock_channels();
                        if let Some(slot) = slot_for_mut(&mut *chs, ch) {
                            slot.apply_close();
                        }
                    }
                    if let Some(signal) = self.shared.signals.get(ch.slot) {
                        signal.wake();
                    }
                    return Err(Error::ChannelClosed);
                }
                _ => self.dispatch(pkt).await?,
            }
        }
    }

    fn channel_ids(&self, ch: ChannelId) -> Result<(u32, u32), Error<<RH as ErrorType>::Error>> {
        let chs = self.shared.lock_channels();
        channel_ids_of(&*chs, ch)
    }

    /// Wait for a device-initiated channel (`adb reverse` traffic and
    /// the like) and hand it over for a verdict.
    ///
    /// Packets for other channels keep being dispatched while waiting.
    /// The returned [`SplitIncoming`] borrows the reader until
    /// [`accept`](SplitIncoming::accept) or
    /// [`reject`](SplitIncoming::reject) resolves it; dropping it
    /// undecided puts the request back at the head of the queue.
    pub async fn accept_incoming(
        &mut self,
    ) -> Result<SplitIncoming<'_, RH, WH, MC, MP, MF>, Error<<RH as ErrorType>::Error>> {
        self.shared.desync.check()?;
        loop {
            let pending = self.shared.lock_incoming().pop_front();
            if let Some(pending) = pending {
                return Ok(SplitIncoming {
                    reader: self,
                    pending: Some(pending),
                });
            }
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.config.max_payload(),
            )
            .await?;
            self.dispatch(pkt).await?;
        }
    }

    /// [`accept_incoming`](Self::accept_incoming) without waiting:
    /// takes a request that already arrived, if any.
    pub fn try_accept_incoming(&mut self) -> Option<SplitIncoming<'_, RH, WH, MC, MP, MF>> {
        let pending = self.shared.lock_incoming().pop_front()?;
        Some(SplitIncoming {
            reader: self,
            pending: Some(pending),
        })
    }

    async fn dispatch(&mut self, pkt: Packet) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let outcome = {
            let mut chs = self.shared.lock_channels();
            dispatch_packet(
                &mut *chs,
                &pkt,
                self.shared.delayed_ack,
                self.shared.config.rx_cap(),
                self.shared.config.rx_watermark(),
            )?
        };

        match outcome {
            DispatchOutcome::AckWrite {
                local_id,
                remote_id,
                len,
            } => {
                let mut wh = self.shared.write_half.lock().await;
                send_okay_to(
                    &mut *wh,
                    &self.shared.desync,
                    self.shared.delayed_ack,
                    local_id,
                    remote_id,
                    len,
                    self.shared.checksum(),
                )
                .await?;
            }
            DispatchOutcome::CreditGranted { idx } => {
                self.shared.signals[idx].wake();
            }
            DispatchOutcome::SlotClosed { idx } => {
                self.shared.signals[idx].wake();
            }
            DispatchOutcome::IncomingOpen {
                remote_id,
                credit,
                destination,
            } => {
                // Bounded by the channel table: past that, an OPEN
                // storm is refused on arrival rather than remembered.
                let queued = {
                    let mut q = self.shared.lock_incoming();
                    if q.len() >= MC {
                        false
                    } else {
                        q.push_back(PendingOpen {
                            remote_id,
                            credit,
                            destination,
                        });
                        true
                    }
                };
                if !queued {
                    let mut wh = self.shared.write_half.lock().await;
                    send_pkt(
                        &mut *wh,
                        &self.shared.desync,
                        &Packet::close(0, remote_id),
                        self.shared.checksum(),
                    )
                    .await?;
                }
            }
            DispatchOutcome::CancelPendingOpen { remote_id } => {
                self.shared
                    .lock_incoming()
                    .retain(|p| p.remote_id != remote_id);
            }
            DispatchOutcome::DataBuffered => {}
            DispatchOutcome::Unmatched => {}
        }
        Ok(())
    }
}

/// A device-initiated channel awaiting a verdict, on a split
/// connection. Dropping it undecided puts the request back at the
/// head of the queue.
pub struct SplitIncoming<'r, RH, WH, const MC: usize, const MP: usize, const MF: usize>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    reader: &'r mut Reader<RH, WH, MC, MP, MF>,
    pending: Option<PendingOpen>,
}

impl<RH, WH, const MC: usize, const MP: usize, const MF: usize>
    SplitIncoming<'_, RH, WH, MC, MP, MF>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
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
    pub async fn accept(mut self) -> Result<ChannelId, Error<<RH as ErrorType>::Error>> {
        let pending = self.pending.take().expect("undecided");
        let shared = &self.reader.shared;
        let checksum = shared.checksum();

        let slot_idx = {
            let mut chs = shared.lock_channels();
            match chs.iter().position(|s| s.is_none()) {
                Some(idx) => {
                    let local_id = shared.next_local_id();
                    let mut slot = ChannelSlot::new(local_id);
                    slot.remote_id = pending.remote_id;
                    slot.state = ChannelState::Open;
                    if shared.delayed_ack {
                        // OPEN's arg1 is the device's receive credit —
                        // our budget.
                        slot.send_budget = i64::from(pending.credit);
                    }
                    let id = slot.local_id;
                    chs[idx] = Some(slot);
                    Ok((idx, id))
                }
                None => Err(()),
            }
        };
        let (slot_idx, local_id) = match slot_idx {
            Ok(pair) => pair,
            Err(()) => {
                let mut wh = shared.write_half.lock().await;
                send_pkt(
                    &mut *wh,
                    &shared.desync,
                    &Packet::close(0, pending.remote_id),
                    checksum,
                )
                .await?;
                return Err(Error::NoFreeChannels);
            }
        };

        let credit_bytes;
        let payload: &[u8] = if shared.delayed_ack {
            credit_bytes = shared.config.advertised_ack_bytes().to_le_bytes();
            &credit_bytes
        } else {
            &[]
        };
        {
            let mut wh = shared.write_half.lock().await;
            send_pkt(
                &mut *wh,
                &shared.desync,
                &Packet::new(
                    Command::Ready,
                    local_id,
                    pending.remote_id,
                    payload.to_vec(),
                ),
                checksum,
            )
            .await?;
        }

        Ok(ChannelId {
            slot: slot_idx,
            local_id,
        })
    }

    /// Refuse the channel: answers CLSE and frees nothing, since
    /// nothing was allocated.
    pub async fn reject(mut self) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let pending = self.pending.take().expect("undecided");
        let shared = &self.reader.shared;
        let checksum = shared.checksum();
        let mut wh = shared.write_half.lock().await;
        send_pkt(
            &mut *wh,
            &shared.desync,
            &Packet::close(0, pending.remote_id),
            checksum,
        )
        .await
    }
}

impl<RH, WH, const MC: usize, const MP: usize, const MF: usize> Drop
    for SplitIncoming<'_, RH, WH, MC, MP, MF>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.reader.shared.lock_incoming().push_front(pending);
        }
    }
}

/// Write half of a split [`Connection`](crate::Connection).
///
/// Cheaply cloneable (an `Arc` bump). Methods take `&self`, so a single
/// `Writer` can be shared across threads with no additional wrapping.
pub struct Writer<
    WH,
    const MAX_CHANNELS: usize = DEFAULT_MAX_CHANNELS,
    const MAX_PROPERTIES: usize = DEFAULT_MAX_PROPERTIES,
    const MAX_FEATURES: usize = DEFAULT_MAX_FEATURES,
> where
    WH: Write,
{
    shared: Arc<Shared<WH, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>>,
}

impl<WH, const MC: usize, const MP: usize, const MF: usize> Clone for Writer<WH, MC, MP, MF>
where
    WH: Write,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<WH, const MC: usize, const MP: usize, const MF: usize> Writer<WH, MC, MP, MF>
where
    WH: Write,
{
    pub(crate) fn new(shared: Arc<Shared<WH, MC, MP, MF>>) -> Self {
        Self { shared }
    }

    /// Maximum payload size for outbound packets.
    pub fn max_payload(&self) -> u32 {
        self.shared.max_payload
    }

    /// Resource limits this connection was opened with.
    pub fn config(&self) -> &ConnectionConfig {
        &self.shared.config
    }

    /// Whether delayed-ACK flow control was negotiated.
    pub fn delayed_ack(&self) -> bool {
        self.shared.delayed_ack
    }

    /// Protocol version in effect: `min(ADB_VERSION, device version)`.
    pub fn protocol_version(&self) -> u32 {
        self.shared.protocol_version
    }

    /// Raw device banner bytes from the CNXN handshake.
    ///
    /// Lock-free connection metadata — available even while the
    /// [`Reader`] is blocked in a read on another thread.
    pub fn device_banner(&self) -> Option<&[u8]> {
        self.shared.device_banner.as_ref().map(|b| b.raw())
    }

    /// Parsed device banner from the CNXN handshake.
    ///
    /// Lock-free connection metadata — available even while the
    /// [`Reader`] is blocked in a read on another thread.
    pub fn device_banner_parsed(&self) -> Option<&DeviceBanner<MP, MF>> {
        self.shared.device_banner.as_ref()
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
    /// paired [`Reader`]. Close it and open a new one.
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
        let max = (self.shared.max_payload as usize).max(1);
        let checksum = self.shared.checksum();

        let mut offset = 0;
        while offset < data.len() {
            let want = (data.len() - offset).min(max);
            let n = self.acquire_credit(ch, want).await?;
            let mut guard = CreditGuard::new(&self.shared, ch, n);

            let (local_id, remote_id) = self.channel_ids(ch)?;
            let chunk = &data[offset..offset + n];

            {
                let mut wh = self.shared.write_half.lock().await;
                send_raw(
                    &mut *wh,
                    &self.shared.desync,
                    Command::Write,
                    local_id,
                    remote_id,
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
        self.shared.desync.check()?;
        let (local_id, remote_id) = self.channel_ids(ch)?;
        {
            let mut wh = self.shared.write_half.lock().await;
            send_pkt(
                &mut *wh,
                &self.shared.desync,
                &Packet::close(local_id, remote_id),
                self.shared.checksum(),
            )
            .await?;
        }
        {
            let mut chs = self.shared.lock_channels();
            if let Some(slot) = chs.get_mut(ch.slot) {
                if slot.as_ref().is_some_and(|s| s.local_id == ch.local_id) {
                    *slot = None;
                }
            }
        }
        if let Some(signal) = self.shared.signals.get(ch.slot) {
            signal.wake();
        }
        Ok(())
    }

    fn channel_ids(&self, ch: ChannelId) -> Result<(u32, u32), Error<<WH as ErrorType>::Error>> {
        let chs = self.shared.lock_channels();
        channel_ids_of(&*chs, ch)
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
            let Some(slot) = slot_for_mut(&mut *chs, ch) else {
                return Err(Error::ChannelClosed);
            };
            if slot.is_closed() {
                return Err(Error::ChannelClosed);
            }
            slot.send_enqueue()
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
                None => listener.await,
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
        let Some(slot) = slot_for_mut(&mut *chs, ch) else {
            return Some(Err(Error::ChannelClosed));
        };
        if slot.is_closed() {
            return Some(Err(Error::ChannelClosed));
        }
        if slot.send_turn() != place {
            return None;
        }
        slot.try_reserve_send(want, self.shared.delayed_ack)
            .map(|n| {
                slot.send_advance();
                Ok((n, slot.send_budget > 0))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::mock::{abandon, now, split_with_channel};

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
            slot_for_mut(&mut *chs, ch)
                .unwrap()
                .apply_ready(&credit.to_le_bytes(), true)
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
