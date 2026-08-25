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

use crate::base::channel::{
    channel_ids_of, dispatch_packet, slot_for_mut, ChannelId, ChannelSlot, DispatchOutcome,
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
            self.shared.config.initial_ack_bytes()
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
        {
            let mut chs = self.shared.lock_channels();
            let slot = slot_for_mut(&mut *chs, ch).ok_or(Error::ChannelClosed)?;
            if !slot.rx_buf.is_empty() {
                let n = buf.len().min(slot.rx_buf.len());
                buf[..n].copy_from_slice(&slot.rx_buf[..n]);
                let _ = slot.rx_buf.split_to(n);
                return Ok(n);
            }
            if slot.is_closed() {
                return Err(Error::ChannelClosed);
            }
        }

        let (local_id, remote_id) = self.channel_ids(ch)?;

        loop {
            let pkt = recv_pkt(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Write if pkt.arg1 == local_id => {
                    let payload_len = pkt.data.len();
                    {
                        let mut wh = self.shared.write_half.lock().await;
                        send_okay_to(
                            &mut *wh,
                            &self.shared.desync,
                            self.shared.delayed_ack,
                            local_id,
                            remote_id,
                            payload_len,
                            self.shared.checksum(),
                        )
                        .await?;
                    }

                    let n = buf.len().min(pkt.data.len());
                    buf[..n].copy_from_slice(&pkt.data[..n]);
                    if n < pkt.data.len() {
                        let mut chs = self.shared.lock_channels();
                        if let Some(slot) = slot_for_mut(&mut *chs, ch) {
                            slot.push_rx(&pkt.data[n..], self.shared.config.rx_cap())?;
                        }
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

    async fn dispatch(&mut self, pkt: Packet) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let outcome = {
            let mut chs = self.shared.lock_channels();
            dispatch_packet(
                &mut *chs,
                &pkt,
                self.shared.delayed_ack,
                self.shared.config.rx_cap(),
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
            DispatchOutcome::SlotUpdated { idx } => {
                self.shared.signals[idx].wake();
            }
            DispatchOutcome::Unmatched => {}
        }
        Ok(())
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
    /// channel never consume the same credit.
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

        loop {
            let listener = signal.listen();
            if let Some(result) = self.try_reserve(ch, want) {
                return result;
            }
            listener.await;
        }
    }

    fn try_reserve(
        &self,
        ch: ChannelId,
        want: usize,
    ) -> Option<Result<usize, Error<<WH as ErrorType>::Error>>> {
        let mut chs = self.shared.lock_channels();
        let Some(slot) = slot_for_mut(&mut *chs, ch) else {
            return Some(Err(Error::ChannelClosed));
        };
        if slot.is_closed() {
            return Some(Err(Error::ChannelClosed));
        }
        slot.try_reserve_send(want, self.shared.delayed_ack).map(Ok)
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
