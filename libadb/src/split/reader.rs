//! [`Reader`], the half that receives packets and dispatches them to
//! the channels they are for.

use alloc::sync::Arc;
use bytes::BytesMut;
use core::convert::Infallible;
use core::pin::pin;
use core::sync::atomic::Ordering;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::shared::{Owed, Shared, SlotGuard};
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
use crate::base::wire::{connection_gone, ends_connection, recv_pkt_or, Received};
use crate::device_banner::DeviceBanner;
use crate::error::Error;
use crate::transport::ReadCancelSafety;

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
    RH: Read + ReadCancelSafety,
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
    pub fn device_banner(&self) -> &[u8] {
        self.shared.negotiated.device_banner.raw()
    }

    /// Parsed device banner from the CNXN handshake.
    pub fn device_banner_parsed(&self) -> &DeviceBanner {
        &self.shared.negotiated.device_banner
    }

    /// Fail with [`Error::MissingFeature`] unless the device banner
    /// lists `feature`.
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
        self.shared.check_live()?;
        let (ch, mut guard) = self.shared.send_open(destination).await?;
        self.await_open_ack(ch, &mut guard).await
    }

    /// Refuse queued OPENs past the cap, which a dropped refusal left
    /// behind, before taking any new packet in. The intake loops that
    /// can run with a full queue start here, so repeated cancellation
    /// cannot grow the queue beyond one past the cap. (`accept_incoming`
    /// needs no barrier: it only reads with the queue empty.)
    async fn drain_overflow(&mut self) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let cap = self.shared.negotiated.config.max_channels();
        while let Some(excess) = self.shared.take_incoming_past(cap) {
            match excess.reject().await {
                // The device is gone, but what it sent can still be
                // received.
                Err(e) if connection_gone(&e) => {}
                refused => refused?,
            }
        }
        Ok(())
    }

    /// The next packet off the connection, once what is owed is out: the
    /// device may be waiting for that, and receiving nothing until then
    /// is what bounds the list.
    ///
    /// The call that sees the connection end gets the failure as it is,
    /// and everyone waiting is told here, since nobody else can see it.
    ///
    /// A write abandoned or a debt falling due ends the wait for a
    /// packet, as the device may send nothing until that is seen to: at
    /// once if the read can be dropped, otherwise with the next packet.
    async fn recv(&mut self) -> Result<Packet, Error<<RH as ErrorType>::Error>> {
        loop {
            self.shared.check_live()?;
            self.shared.pay().await?;
            let race = self.read_half.read_cancel_safe();
            let received = recv_pkt_or(
                &mut self.read_half,
                &mut self.recv_buf,
                self.shared.negotiated.config.max_payload(),
                pin!(self.shared.receive_interrupted(race)),
                race,
            )
            .await;
            match received {
                Ok(Received::Packet(pkt)) => return Ok(pkt),
                Ok(Received::Interrupted(())) => {}
                Err(e) => {
                    if ends_connection(&e) {
                        self.shared.end_stream();
                    }
                    return Err(e);
                }
            }
        }
    }

    async fn await_open_ack(
        &mut self,
        ch: ChannelId,
        guard: &mut SlotGuard<WH>,
    ) -> Result<ChannelId, Error<<RH as ErrorType>::Error>> {
        self.drain_overflow().await?;
        loop {
            let pkt = self.recv().await?;
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
    /// A write abandoned mid-packet ends it too, with
    /// [`Error::Desynchronized`], as the device may never send another
    /// packet: at once on a transport whose reads can be dropped, and at
    /// the next packet on one whose reads cannot, as
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety) reports
    /// of USB.
    ///
    /// Channels the device opens toward the host (`adb reverse`) wait
    /// for an [`IncomingListener`] while one is alive, and are refused
    /// otherwise. Requests still queued when the last listener goes are
    /// refused once the next packet arrives.
    ///
    /// A packet that breaks one channel alone, with data past its
    /// receive cap or a READY it cannot take, closes that channel: the
    /// device gets its CLSE, and the channel's calls fail with that
    /// error once what it buffered before is read.
    ///
    /// Without delayed ACK, data is acknowledged from here as it
    /// arrives, so the OKAY may reach the device after packets a task
    /// sends in response to that data. The protocol allows either order.
    ///
    /// A read that is not cancel-safe (USB) is never cancelled from
    /// within, so this is also the way to read such a transport from
    /// several tasks. Dropping the future stops reception like any
    /// dropped read on such a transport, and is otherwise the way to
    /// shut the connection down.
    pub async fn run(mut self) -> Result<Infallible, Error<<RH as ErrorType>::Error>> {
        self.shared.check_live()?;
        loop {
            // Before every receive, the first included, so nothing left
            // over — from before `run` or by the last packet — waits for
            // traffic that may never come: requests nobody listens for
            // are refused, and `recv` pays what is owed.
            if self.shared.listeners.load(Ordering::Acquire) == 0 {
                while let Some(refused) = self.shared.take_incoming() {
                    match refused.reject().await {
                        // The device is gone, but what it sent can still
                        // be received.
                        Err(e) if connection_gone(&e) => {}
                        refused => refused?,
                    }
                }
            }
            let pkt = self.recv().await?;
            self.dispatch(pkt, OnFault::CloseChannel).await?;
        }
    }

    /// Take one packet off the connection and act on it: wake whoever
    /// waits on the channel it is for, or keep it for a later read.
    ///
    /// For a caller that keeps the `Reader` and has no task to give
    /// [`run`](Self::run). A [`Writer::write_channel`] parked for credit
    /// has nobody else to take the OKAY it waits for when no read is
    /// under way; [`Writer::waits_for_credit`] says when that is.
    ///
    /// It waits for a packet, however long one takes. On a transport
    /// whose reads are not cancel-safe the future must not be dropped:
    /// see [Dropping a call](crate::split#dropping-a-call).
    ///
    /// A packet that breaks one channel alone closes that channel, as
    /// under [`run`](Self::run), and is not this call's failure. Unlike
    /// `run`, this leaves a channel the device opens queued for
    /// [`accept_incoming`](Self::accept_incoming), with or without an
    /// [`IncomingListener`] alive.
    pub async fn dispatch_one(&mut self) -> Result<(), Error<<RH as ErrorType>::Error>> {
        self.shared.check_live()?;
        self.drain_overflow().await?;
        let pkt = self.recv().await?;
        self.dispatch(pkt, OnFault::CloseChannel).await
    }

    /// Read from channel `ch` into `buf`. Returns the number of bytes read.
    ///
    /// Returns immediately if data is already buffered; otherwise blocks
    /// reading packets until data for `ch` arrives (dispatching packets
    /// for other channels in the meantime). A zero-length WRTE delivers
    /// nothing and is read past, so `Ok(0)` only answers an empty `buf`.
    ///
    /// What is buffered is handed over first, however the connection
    /// fails: see [What arrived stays readable](crate::split#what-arrived-stays-readable).
    /// A write abandoned mid-packet ends the wait for a packet, as it
    /// ends [`run`](Self::run). Nothing receives while this call waits
    /// for the write half, so the end of the stream cannot reach it
    /// there.
    ///
    /// Safe to drop while it waits for the write half: nothing has been
    /// taken, and the next read gets the bytes. Dropped while it waits
    /// for a packet, it drops a transport read: see
    /// [Dropping a call](crate::split#dropping-a-call).
    ///
    /// A concurrent [`Writer::close_channel`] on the same channel does
    /// not wake this call: see
    /// [Closing while a read waits](crate::split#closing-while-a-read-waits).
    pub async fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<<RH as ErrorType>::Error>> {
        // Here too: a read that has its data waits for no packet, and
        // the device, owed an OKAY, may never send one. A failure here is
        // a desync, reported once nothing is left to hand over.
        let _ = self.shared.pay().await;
        if let Some(n) = self.shared.take_buffered(ch, buf).await? {
            return Ok(n);
        }

        self.channel_ids(ch)?;

        self.drain_overflow().await?;
        loop {
            let pkt = self.recv().await?;
            // What the packet left for this channel goes first: what
            // failed along the way is the next call's to report.
            let dispatched = self.dispatch(pkt, OnFault::FailCall).await;
            match (self.shared.take_buffered(ch, buf).await, dispatched) {
                (Ok(Some(n)), _) => return Ok(n),
                (_, Err(e)) | (Err(e), _) => return Err(e),
                (Ok(None), Ok(())) => {}
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
    /// The returned [`SplitIncoming`] owns the request, so it can be
    /// held across other calls until [`accept`](SplitIncoming::accept)
    /// or [`reject`](SplitIncoming::reject) resolves it; dropping it
    /// undecided puts the request back at the head of the queue.
    ///
    /// Dropped while it waits for a packet, it drops a transport read:
    /// see [Dropping a call](crate::split#dropping-a-call).
    pub async fn accept_incoming(
        &mut self,
    ) -> Result<SplitIncoming<WH>, Error<<RH as ErrorType>::Error>> {
        self.shared.check_live()?;
        self.shared.pay().await?;
        loop {
            if let Some(incoming) = self.shared.take_incoming() {
                return Ok(incoming);
            }
            let pkt = self.recv().await?;
            self.dispatch(pkt, OnFault::FailCall).await?;
        }
    }

    /// [`accept_incoming`](Self::accept_incoming) without waiting:
    /// takes a request that already arrived, if any.
    pub fn try_accept_incoming(&mut self) -> Option<SplitIncoming<WH>> {
        self.shared.take_incoming()
    }

    /// Act on `pkt`, ignoring a failed answer if the device is gone:
    /// there is nobody to answer, and what it sent can still be received.
    async fn dispatch(
        &mut self,
        pkt: Packet,
        on_fault: OnFault,
    ) -> Result<(), Error<<RH as ErrorType>::Error>> {
        match self.act_on(pkt, on_fault).await {
            Err(e) if connection_gone(&e) => Ok(()),
            acted => acted,
        }
    }

    async fn act_on(
        &mut self,
        pkt: Packet,
        on_fault: OnFault,
    ) -> Result<(), Error<<RH as ErrorType>::Error>> {
        let outcome = { self.shared.lock_channels().dispatch(&pkt) };

        match outcome {
            DispatchOutcome::AckWrite { idx, ack } => {
                self.shared.signals[idx].wake();
                self.shared.owe(Owed::Okay(ack));
                self.shared.pay().await?;
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
                self.shared.owe(Owed::Close(ids));
                self.shared.pay().await?;
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

    /// Release the channel slot and send CLSE:
    /// [`Writer::close_channel`] on the read half, so an open-read-close
    /// service exchange can run on the `Reader` alone. Nothing receives
    /// while this call waits for the write half, so the end of the
    /// stream cannot reach it there.
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
    RH: Read + ReadCancelSafety,
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
