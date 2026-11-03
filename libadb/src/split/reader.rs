//! [`Reader`], the half that receives packets and dispatches them to
//! the channels they are for.

use alloc::sync::Arc;
use bytes::BytesMut;
use core::convert::Infallible;
use core::sync::atomic::Ordering;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::shared::{Shared, SlotGuard};
use super::writer::close_channel_via;
use super::SplitIncoming;
use crate::base::channel::ChannelId;
use crate::base::channel_table::DispatchOutcome;
use crate::base::connection::ConnectionConfig;
use crate::base::ids::{ChannelIds, RemoteId};
use crate::base::incoming::PendingOpen;
use crate::base::protocol::command::Command;
use crate::base::protocol::Packet;
use crate::base::session::ServiceChannel;
use crate::base::slot::ChannelFault;
use crate::base::wire::{recv_pkt, send_pkt};
use crate::device_banner::DeviceBanner;
use crate::error::Error;

#[cfg(doc)]
use super::{IncomingListener, Writer};

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
    pub(super) shared: Arc<Shared<WH>>,
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
                        match chs.get_mut(ch) {
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
                        match chs.get_mut(ch) {
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
                        if let Some(slot) = chs.get_mut(ch) {
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
        self.shared.lock_channels().ids(ch)
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
        let outcome = { self.shared.lock_channels().dispatch(&pkt) };

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
                let pending = PendingOpen {
                    remote,
                    credit,
                    destination,
                };
                self.shared.queue_or_refuse(pending).await?;
            }
            DispatchOutcome::CancelPendingOpen { remote } => {
                self.shared.withdraw_open(remote);
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

impl<RH, WH> ServiceChannel for Reader<RH, WH>
where
    RH: Read,
    WH: Write<Error = <RH as ErrorType>::Error>,
{
    type IoError = <RH as ErrorType>::Error;

    async fn open_service_channel(
        &mut self,
        dest: &[u8],
    ) -> Result<ChannelId, Error<Self::IoError>> {
        self.open_channel(dest).await
    }

    async fn read_service_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<Self::IoError>> {
        self.read_channel(ch, buf).await
    }

    async fn close_service_channel(&mut self, ch: ChannelId) -> Result<(), Error<Self::IoError>> {
        self.close_channel(ch).await
    }
}
