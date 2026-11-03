mod accept;
mod banner;
mod config;
mod handshake;
#[cfg(test)]
mod tests;
#[cfg(feature = "tls")]
mod tls;

pub use accept::Incoming;
pub use banner::HostBanner;
pub use config::{ConnectionConfig, MIN_MAX_PAYLOAD};

use bytes::BytesMut;
use core::convert::Infallible;
use core::future::{pending, Future};
use core::pin::pin;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::channel::{Channel, ChannelId, SelectResult};
use super::channel_table::{ChannelTable, DispatchOutcome};
use super::device_banner::DeviceBanner;
use super::ids::{ChannelIds, RemoteId};
use super::incoming::{IncomingQueue, PendingOpen};
use super::negotiated::Negotiated;
use super::protocol::command::Command;
use super::protocol::features::Feature;
use super::protocol::Packet;
use super::slot::{ChannelSlot, PendingAck};
use super::wire::{
    recv_pkt, recv_pkt_or, send_okay_to, send_open, send_pkt, send_raw, DesyncFlag, Received,
};
use crate::error::Error;

/// ADB connection over an async transport.
pub struct Connection<T>
where
    T: Read + Write,
{
    transport: T,
    /// [`ConnectionConfig::max_channels`] slots, allocated up front.
    table: ChannelTable,
    negotiated: Negotiated,
    recv_buf: BytesMut,
    pub(crate) desync: DesyncFlag,
    /// Device-initiated OPENs awaiting [`accept_incoming`]. Bounded by
    /// the size of the table; overflow is refused with CLSE on
    /// arrival.
    ///
    /// [`accept_incoming`]: Self::accept_incoming
    incoming: IncomingQueue,
}

/// What a connection is made of, handed over whole when it is split.
#[cfg(feature = "split")]
pub(crate) struct SplitParts<T> {
    /// The transport, still in one piece.
    pub(crate) transport: T,
    /// Whatever of a packet was read and not decoded yet.
    pub(crate) recv_buf: BytesMut,
    /// What the handshake settled.
    pub(crate) negotiated: Negotiated,
    /// The channels, open or opening.
    pub(crate) table: ChannelTable,
    /// Device-initiated OPENs still waiting for a verdict.
    pub(crate) incoming: IncomingQueue,
    /// Whether a packet was already abandoned mid-write.
    pub(crate) desync: DesyncFlag,
}

impl<T> Connection<T>
where
    T: Read + Write,
{
    /// Maximum payload size for outbound packets: the smaller of what
    /// the device advertised in its CNXN and what this library can
    /// encode.
    pub fn max_payload(&self) -> u32 {
        self.negotiated.max_payload
    }

    /// Resource limits this connection was opened with.
    ///
    /// [`ConnectionConfig::max_payload`] is the inbound direction — what
    /// this host advertised to the device — while
    /// [`max_payload`](Self::max_payload) is the outbound one.
    pub fn config(&self) -> &ConnectionConfig {
        &self.negotiated.config
    }

    /// Protocol version in effect: `min(ADB_VERSION, device version)`.
    ///
    /// At or above
    /// [`ADB_VERSION_SKIP_CHECKSUM`](crate::protocol::constant::ADB_VERSION_SKIP_CHECKSUM)
    /// outgoing packets leave `data_check` zero, as `adb` itself does.
    pub fn protocol_version(&self) -> u32 {
        self.negotiated.protocol_version
    }

    /// Raw device banner bytes received during CNXN handshake.
    pub fn device_banner(&self) -> &[u8] {
        self.negotiated.device_banner.raw()
    }

    /// Parsed device banner received during CNXN handshake. Every
    /// connection has one: a banner that does not parse fails the
    /// handshake.
    pub fn device_banner_parsed(&self) -> &DeviceBanner {
        &self.negotiated.device_banner
    }

    /// Fail with [`Error::MissingFeature`] unless the device banner
    /// lists `feature`.
    pub fn require_feature(&self, feature: Feature) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.negotiated.require_feature(feature)
    }

    /// Whether delayed ACK (credit-based flow control) is enabled.
    pub fn delayed_ack(&self) -> bool {
        self.negotiated.delayed_ack
    }

    /// Everything the handshake settled, for the crate's own helpers.
    pub(crate) fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// Reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consume the connection, returning the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Consume the connection, returning the transport and the internal
    /// receive buffer (which may contain a partial packet read earlier).
    pub fn into_parts(self) -> (T, BytesMut) {
        (self.transport, self.recv_buf)
    }

    /// Consume the connection and split it into a [`Reader`](crate::Reader)
    /// / [`Writer`](crate::Writer) pair that can be driven from different
    /// threads/tasks concurrently.
    ///
    /// Requires the transport to implement [`Splittable`](crate::Splittable).
    /// Splitting can fail if the underlying transport cannot duplicate its
    /// endpoint (e.g. [`std::net::TcpStream::try_clone`] returning an
    /// error); in that case the connection is consumed and the error is
    /// returned.
    #[cfg(feature = "split")]
    #[allow(clippy::type_complexity)]
    pub fn split(
        self,
    ) -> Result<
        (
            crate::split::Reader<
                <T as crate::Splittable>::ReadHalf,
                <T as crate::Splittable>::WriteHalf,
            >,
            crate::split::Writer<<T as crate::Splittable>::WriteHalf>,
        ),
        Error<<T as ErrorType>::Error>,
    >
    where
        T: crate::Splittable,
    {
        use crate::split::{Reader, Shared, Writer};
        use alloc::sync::Arc;

        let parts = self.into_split_parts();
        let (read_half, write_half) = parts.transport.split().map_err(Error::Io)?;
        let shared = Arc::new(Shared::new(
            write_half,
            parts.negotiated,
            parts.table,
            parts.incoming,
            parts.desync,
        ));
        let reader = Reader::new(read_half, parts.recv_buf, Arc::clone(&shared));
        Ok((reader, Writer::new(shared)))
    }

    #[cfg(feature = "split")]
    fn into_split_parts(self) -> SplitParts<T> {
        SplitParts {
            transport: self.transport,
            recv_buf: self.recv_buf,
            negotiated: self.negotiated,
            table: self.table,
            incoming: self.incoming,
            desync: self.desync,
        }
    }

    /// Open a channel and return a [`Channel`] handle that borrows this
    /// connection.
    ///
    /// Only one `Channel` can exist at a time (it holds `&mut self`).
    /// For multiplexed access to several channels, use
    /// [`open_channel`](Self::open_channel) + [`ChannelId`]-based methods.
    pub async fn open(
        &mut self,
        destination: &[u8],
    ) -> Result<Channel<'_, Self>, Error<<T as ErrorType>::Error>>
    where
        T: crate::transport::ReadCancelSafety,
    {
        crate::base::session::Session::open(self, destination).await
    }

    /// Open a channel, returning a [`ChannelId`] for multiplexed use.
    ///
    /// The destination is a null-terminated string like `b"shell:ls\0"`,
    /// `b"tcp:8080\0"`, `b"sync:\0"`, etc.
    ///
    /// In delayed ACK mode, `arg1` of the OPEN message carries the desired
    /// Available Send Bytes (ASB), and the OKAY response payload contains
    /// the initial send budget granted by the device.
    ///
    /// **Not cancellation-safe.** Dropping the future after the OPEN
    /// packet has been sent gives the channel up before the device
    /// answers. Should it accept after all, the next call that reads
    /// the connection answers its READY with CLSE, so the device's end
    /// does not stay open; the same goes for an `Err` returned before
    /// the answer. Dropping it mid-packet is worse: see
    /// [`write_channel`](Self::write_channel).
    pub async fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        // The slot stays free until the device answers: an opener given
        // up on leaves nothing behind, and its READY, should it come,
        // finds no channel and is answered with CLSE. Nothing takes the
        // slot meanwhile, since dispatch only touches slots in use.
        let ch = self.table.allocate()?;
        let credit = self.negotiated.advertised_credit().unwrap_or(0);
        let checksum = self.negotiated.checksum();
        send_open(
            &mut self.transport,
            &self.desync,
            ch.local,
            credit,
            destination,
            checksum,
        )
        .await?;

        self.await_open_ack(ch).await
    }

    async fn await_open_ack(
        &mut self,
        ch: ChannelId,
    ) -> Result<ChannelId, Error<<T as ErrorType>::Error>> {
        loop {
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.negotiated.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Ready if pkt.arg1 == ch.local.raw() => {
                    let remote = RemoteId::from(pkt.arg0);
                    let slot = self.table.insert_opening(ch);
                    if let Err(e) = slot.accept_open_ready(remote, &pkt.data) {
                        self.table.free(ch);
                        // The device holds an end it takes for open:
                        // close it by its id.
                        let checksum = self.negotiated.checksum();
                        let ids = ChannelIds {
                            local: ch.local,
                            remote,
                        };
                        send_pkt(
                            &mut self.transport,
                            &self.desync,
                            &Packet::close(ids),
                            checksum,
                        )
                        .await?;
                        return Err(e.into());
                    }
                    return Ok(ch);
                }
                Command::Close if pkt.arg1 == ch.local.raw() => {
                    return Err(Error::ChannelClosed);
                }
                _ => {
                    self.dispatch(pkt).await?;
                }
            }
        }
    }

    /// Read data from a channel into `buf`. Returns the number of bytes read.
    ///
    /// If data is already buffered, returns immediately. Otherwise blocks until
    /// a WRTE message arrives for this channel (buffering messages for others).
    ///
    /// Reading is what re-opens the sender's window. With delayed ACK,
    /// credit is returned for exactly the bytes taken here, and what
    /// was advertised in OPEN bounds the rest. Without it, an inbound
    /// write is still acknowledged on arrival while the channel holds
    /// less than [`ConnectionConfig::rx_watermark`] unread bytes; past
    /// that, the acknowledgement waits for the read. Either way a
    /// channel nobody reads stops the device writing to it rather than
    /// growing without bound.
    ///
    /// [`ConnectionConfig::rx_watermark`]: crate::ConnectionConfig::rx_watermark
    pub async fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<<T as ErrorType>::Error>> {
        match self
            .recv_data(ch, buf, pending::<Infallible>(), true)
            .await?
        {
            SelectResult::Data(n) => Ok(n),
            SelectResult::Interrupted(never) => match never {},
        }
    }

    /// Write data to a channel.
    ///
    /// Splits `data` into chunks bounded by `max_payload` and the
    /// currently-granted send budget, waiting for flow-control
    /// acknowledgements between chunks.
    ///
    /// **Not cancellation-safe.** A packet goes out as a header write
    /// followed by a payload write, and dropping the future between
    /// them leaves the device reading whatever we send next as the rest
    /// of that packet. The connection is marked desynchronized instead:
    /// every later operation on it fails with
    /// [`Error::Desynchronized`].
    ///
    /// The mark goes up from the moment the header write is first
    /// polled, not only between the two writes — a transport that took
    /// bytes before returning `Pending` looks no different from one
    /// that took none.
    pub async fn write_channel(
        &mut self,
        ch: ChannelId,
        data: &[u8],
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        if data.is_empty() {
            return Ok(());
        }

        let max = (self.negotiated.max_payload as usize).max(1);
        let checksum = self.negotiated.checksum();

        let mut offset = 0;
        while offset < data.len() {
            self.wait_ack(ch).await?;

            let budget = self.slot_mut(ch)?.budget().unwrap_or(0);
            let n = (data.len() - offset).min(max).min(budget);
            debug_assert!(n > 0, "wait_ack returned with nothing to send");

            let ids = self.table.ids(ch)?;
            send_raw(
                &mut self.transport,
                &self.desync,
                Command::Write,
                ids,
                &data[offset..offset + n],
                checksum,
            )
            .await?;

            self.slot_mut(ch)?.spend(n);
            offset += n;
        }

        Ok(())
    }

    /// Wait for a device-initiated channel (`adb reverse` traffic and
    /// the like) and hand it over for a verdict.
    ///
    /// Packets for other channels keep being dispatched while waiting,
    /// exactly as in [`read_channel`](Self::read_channel). The returned
    /// [`Incoming`] borrows the connection until [`Incoming::accept`]
    /// or [`Incoming::reject`] resolves it; dropping the verdict
    /// undecided puts the request back at the head of the queue and
    /// loses nothing.
    ///
    /// Dropping the future while it still *waits* for a packet is
    /// another matter: the wait is a transport read, so cancelling it
    /// inherits the transport's
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety) — where
    /// reads are not cancel-safe (USB), an abandoned in-flight read can
    /// lose packet bytes, exactly as with a cancelled
    /// [`read_channel`](Self::read_channel).
    ///
    /// Pending requests are bounded by
    /// [`ConnectionConfig::max_channels`]: past that, new OPENs are
    /// refused with CLSE on arrival.
    pub async fn accept_incoming(
        &mut self,
    ) -> Result<Incoming<'_, T>, Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        loop {
            if let Some(pending) = self.incoming.pop_front() {
                return Ok(Incoming {
                    conn: self,
                    pending: Some(pending),
                    reserved: None,
                });
            }
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.negotiated.config.max_payload(),
            )
            .await?;
            self.dispatch(pkt).await?;
        }
    }

    /// [`accept_incoming`](Self::accept_incoming) without waiting:
    /// takes a request that already arrived, if any.
    pub fn try_accept_incoming(&mut self) -> Option<Incoming<'_, T>> {
        let pending = self.incoming.pop_front()?;
        Some(Incoming {
            conn: self,
            pending: Some(pending),
            reserved: None,
        })
    }

    /// Close a channel.
    pub async fn close_channel(
        &mut self,
        ch: ChannelId,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        let ids = self.table.ids(ch)?;
        let checksum = self.negotiated.checksum();
        send_pkt(
            &mut self.transport,
            &self.desync,
            &Packet::close(ids),
            checksum,
        )
        .await?;
        self.table.free(ch);
        Ok(())
    }

    /// Read from a channel, returning early if `interrupt` resolves first.
    ///
    /// How early depends on the transport. Where a read can be dropped
    /// at no cost (an async TCP socket), it is raced against the
    /// interrupt and cancelled the moment it is due. Elsewhere the
    /// interrupt is checked between reads instead: over USB, where
    /// dropping a read would lose data, and over the blocking socket
    /// `Inline` dials, where a read never yields. A read already
    /// blocking cannot be interrupted: it completes first, however long
    /// the device takes, and may return its data ahead of a ready
    /// interrupt. See
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
    ///
    /// After a [`SelectResult::Interrupted`] result the caller can
    /// [`write_channel`](Self::write_channel) and call this method
    /// again — the read resumes cleanly without losing data.
    pub async fn select_channel<F>(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<<T as ErrorType>::Error>>
    where
        F: Future,
        T: crate::transport::ReadCancelSafety,
    {
        let race = self.transport.read_cancel_safe();
        self.recv_data(ch, buf, interrupt, race).await
    }

    /// Buffered data first, then packets off the wire until one is for
    /// `ch`, with `interrupt` and `race` as in [`recv_pkt_or`].
    async fn recv_data<F: Future>(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
        interrupt: F,
        race: bool,
    ) -> Result<SelectResult<F::Output>, Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        let buffered = self.slot_mut(ch)?.take_buffered(buf)?;
        if let Some((n, ack)) = buffered {
            if let Some(ack) = ack {
                self.send_okay(ack).await?;
            }
            return Ok(SelectResult::Data(n));
        }

        let ids = self.table.ids(ch)?;
        let mut interrupt = pin!(interrupt);

        loop {
            let pkt = match recv_pkt_or(
                &mut self.transport,
                &mut self.recv_buf,
                self.negotiated.config.max_payload(),
                interrupt.as_mut(),
                race,
            )
            .await?
            {
                Received::Packet(pkt) => pkt,
                Received::Interrupted(val) => return Ok(SelectResult::Interrupted(val)),
            };
            match pkt.command {
                Command::Write if pkt.arg1 == ids.local.raw() => {
                    let n = buf.len().min(pkt.data.len());
                    buf[..n].copy_from_slice(&pkt.data[..n]);
                    let ack = match self.table.get_mut(ch) {
                        Some(slot) => slot.deliver(&pkt.data, n)?,
                        None => None,
                    };
                    if let Some(ack) = ack {
                        self.send_okay(ack).await?;
                    }
                    return Ok(SelectResult::Data(n));
                }
                Command::Close if ids.closed_by(&pkt) => {
                    if let Some(slot) = self.table.get_mut(ch) {
                        slot.apply_close();
                    }
                    return Err(Error::ChannelClosed);
                }
                _ => {
                    self.dispatch(pkt).await?;
                }
            }
        }
    }

    fn slot_mut(
        &mut self,
        ch: ChannelId,
    ) -> Result<&mut ChannelSlot, Error<<T as ErrorType>::Error>> {
        self.table.get_mut(ch).ok_or(Error::ChannelClosed)
    }

    async fn send_okay(&mut self, ack: PendingAck) -> Result<(), Error<<T as ErrorType>::Error>> {
        let mode = self.negotiated.ack_mode();
        let checksum = self.negotiated.checksum();
        send_okay_to(&mut self.transport, &self.desync, ack, mode, checksum).await
    }

    async fn dispatch(&mut self, pkt: Packet) -> Result<(), Error<<T as ErrorType>::Error>> {
        let checksum = self.negotiated.checksum();
        match self.table.dispatch(&pkt) {
            DispatchOutcome::AckWrite { ack, .. } => self.send_okay(ack).await?,
            DispatchOutcome::IncomingOpen {
                remote,
                credit,
                destination,
            } => {
                // The queue is bounded by the channel table: past that, an
                // OPEN storm is refused on arrival rather than remembered.
                if self.incoming.len() >= self.table.len() {
                    let refusal = Packet::refuse(remote);
                    send_pkt(&mut self.transport, &self.desync, &refusal, checksum).await?;
                } else {
                    self.incoming.push_back(PendingOpen {
                        remote,
                        credit,
                        destination,
                    });
                }
            }
            DispatchOutcome::CancelPendingOpen { remote } => self.incoming.withdraw(remote),
            DispatchOutcome::StrayReady { ids } => {
                let close = Packet::close(ids);
                send_pkt(&mut self.transport, &self.desync, &close, checksum).await?;
            }
            // The fault surfaces on whichever call is driving the
            // connection, and the channel itself stays as it was.
            DispatchOutcome::ChannelFault { fault, .. } => return Err(fault.error()),
            _ => {}
        }
        Ok(())
    }

    async fn wait_ack(&mut self, ch: ChannelId) -> Result<(), Error<<T as ErrorType>::Error>> {
        loop {
            {
                let slot = self.slot_mut(ch)?;
                if slot.budget().is_some() {
                    return Ok(());
                }
                if slot.is_closed() {
                    return Err(Error::ChannelClosed);
                }
            }

            let ids = self.table.ids(ch)?;
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.negotiated.config.max_payload(),
            )
            .await?;

            match pkt.command {
                Command::Ready if pkt.arg1 == ids.local.raw() => {
                    if let Some(slot) = self.table.get_mut(ch) {
                        slot.apply_ready(&pkt.data)?;
                    }
                }
                Command::Close if ids.closed_by(&pkt) => {
                    if let Some(slot) = self.table.get_mut(ch) {
                        slot.apply_close();
                    }
                    return Err(Error::ChannelClosed);
                }
                _ => {
                    self.dispatch(pkt).await?;
                }
            }
        }
    }
}
