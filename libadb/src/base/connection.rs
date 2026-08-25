use bytes::BytesMut;
use core::future::Future;
use core::task::Poll;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::channel::{
    channel_ids_of, dispatch_packet, Channel, ChannelId, ChannelSlot, DispatchOutcome, SelectResult,
};
use super::device_banner::DeviceBanner;
use super::error::Error;
use super::protocol::command::Command;
use super::protocol::features::Feature;
use super::protocol::packet::Packet;
use super::protocol::Checksum;
use super::wire::{recv_pkt, send_okay_to, send_pkt, send_raw, DesyncFlag, Staged, MIN_READ};
pub use config::{ConnectionConfig, MIN_MAX_PAYLOAD};

pub const DEFAULT_MAX_CHANNELS: usize = 32;
pub const DEFAULT_MAX_PROPERTIES: usize = 64;
pub const DEFAULT_MAX_FEATURES: usize = 24;

/// ADB connection over an async transport.
pub struct Connection<
    T,
    const MAX_CHANNELS: usize = DEFAULT_MAX_CHANNELS,
    const MAX_PROPERTIES: usize = DEFAULT_MAX_PROPERTIES,
    const MAX_FEATURES: usize = DEFAULT_MAX_FEATURES,
> where
    T: Read + Write,
{
    transport: T,
    channels: [Option<ChannelSlot>; MAX_CHANNELS],
    max_payload: u32,
    protocol_version: u32,
    config: ConnectionConfig,
    device_banner: Option<DeviceBanner<MAX_PROPERTIES, MAX_FEATURES>>,
    local_id_counter: u32,
    delayed_ack: bool,
    recv_buf: BytesMut,
    pub(crate) desync: DesyncFlag,
}

async fn dispatch_to<T: Write>(
    transport: &mut T,
    desync: &DesyncFlag,
    channels: &mut [Option<ChannelSlot>],
    delayed_ack: bool,
    rx_cap: usize,
    checksum: Checksum,
    pkt: Packet,
) -> Result<(), Error<T::Error>> {
    if let DispatchOutcome::AckWrite {
        local_id,
        remote_id,
        len,
    } = dispatch_packet(channels, &pkt, delayed_ack, rx_cap)?
    {
        send_okay_to(
            transport,
            desync,
            delayed_ack,
            local_id,
            remote_id,
            len,
            checksum,
        )
        .await?;
    }
    Ok(())
}

impl<T, const MAX_CHANNELS: usize, const MAX_PROPERTIES: usize, const MAX_FEATURES: usize>
    Connection<T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    /// Maximum payload size for outbound packets: the smaller of what
    /// the device advertised in its CNXN and what this library can
    /// encode.
    pub fn max_payload(&self) -> u32 {
        self.max_payload
    }

    /// Resource limits this connection was opened with.
    ///
    /// [`ConnectionConfig::max_payload`] is the inbound direction — what
    /// this host advertised to the device — while
    /// [`max_payload`](Self::max_payload) is the outbound one.
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// Protocol version in effect: `min(ADB_VERSION, device version)`.
    ///
    /// At or above
    /// [`ADB_VERSION_SKIP_CHECKSUM`](crate::protocol::constant::ADB_VERSION_SKIP_CHECKSUM)
    /// outgoing packets leave `data_check` zero, as `adb` itself does.
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    fn checksum(&self) -> Checksum {
        Checksum::for_version(self.protocol_version)
    }

    /// Raw device banner bytes received during CNXN handshake.
    pub fn device_banner(&self) -> Option<&[u8]> {
        self.device_banner.as_ref().map(|v| v.raw())
    }

    /// Parsed device banner received during CNXN handshake.
    pub fn device_banner_parsed(&self) -> Option<&DeviceBanner<MAX_PROPERTIES, MAX_FEATURES>> {
        self.device_banner.as_ref()
    }

    /// Fail with [`Error::MissingFeature`] if the device banner was
    /// parsed and does not list `feature`.
    ///
    /// Returns `Ok(())` when the device advertises `feature` or when
    /// no parseable banner is available (e.g. custom transports that
    /// skip the handshake) — the latter is permissive by design so
    /// that feature checks never block a connection that lacks a
    /// banner altogether.
    pub fn require_feature(&self, feature: Feature) -> Result<(), Error<<T as ErrorType>::Error>> {
        match &self.device_banner {
            Some(b) if b.has_feature(&feature) => Ok(()),
            Some(_) => Err(Error::MissingFeature(feature)),
            None => Ok(()),
        }
    }

    /// Whether delayed ACK (credit-based flow control) is enabled.
    pub fn delayed_ack(&self) -> bool {
        self.delayed_ack
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
                MAX_CHANNELS,
                MAX_PROPERTIES,
                MAX_FEATURES,
            >,
            crate::split::Writer<
                <T as crate::Splittable>::WriteHalf,
                MAX_CHANNELS,
                MAX_PROPERTIES,
                MAX_FEATURES,
            >,
        ),
        Error<<T as ErrorType>::Error>,
    >
    where
        T: crate::Splittable,
    {
        use crate::split::{Reader, Shared, Writer};
        use alloc::sync::Arc;
        use core::sync::atomic::AtomicU32;

        let (read_half, write_half) = self.transport.split().map_err(Error::Io)?;

        let shared = Arc::new(Shared {
            write_half: async_lock::Mutex::new(write_half),
            channels: std::sync::Mutex::new(self.channels),
            signals: core::array::from_fn(|_| crate::split::FlowSignal::new()),
            max_payload: self.max_payload,
            protocol_version: self.protocol_version,
            config: self.config,
            delayed_ack: self.delayed_ack,
            device_banner: self.device_banner,
            local_id_counter: AtomicU32::new(self.local_id_counter),
            desync: self.desync,
        });

        let reader = Reader::new(read_half, self.recv_buf, Arc::clone(&shared));
        let writer = Writer::new(shared);
        Ok((reader, writer))
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
    ) -> Result<
        Channel<'_, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
        Error<<T as ErrorType>::Error>,
    > {
        let id = self.open_channel(destination).await?;
        Ok(Channel { conn: self, id })
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
    /// packet has been sent leaves the device-side channel half-open
    /// until the connection is closed — async Drop cannot send the
    /// matching CLSE. If the call returns `Err`, a best-effort CLSE is
    /// sent before the error propagates. Dropping it mid-packet is
    /// worse: see [`write_channel`](Self::write_channel).
    pub async fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        let slot_idx = self
            .channels
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::NoFreeChannels)?;

        let local_id = self.next_local_id();
        let open_arg1 = if self.delayed_ack {
            self.config.initial_ack_bytes()
        } else {
            0
        };
        let pkt = Packet::new(Command::Open, local_id, open_arg1, destination.to_vec());
        let checksum = self.checksum();
        send_pkt(&mut self.transport, &self.desync, &pkt, checksum).await?;

        let result = self.await_open_ack(local_id, slot_idx).await;
        if let Err(ref e) = result {
            if !matches!(e, Error::ChannelClosed) {
                let _ = send_raw(
                    &mut self.transport,
                    &self.desync,
                    Command::Close,
                    local_id,
                    0,
                    &[],
                    checksum,
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
    ) -> Result<ChannelId, Error<<T as ErrorType>::Error>> {
        loop {
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Ready if pkt.arg1 == local_id => {
                    let mut slot = ChannelSlot::new(local_id);
                    slot.accept_open_ready(pkt.arg0, &pkt.data, self.delayed_ack)?;
                    self.channels[slot_idx] = Some(slot);
                    return Ok(ChannelId {
                        slot: slot_idx,
                        local_id,
                    });
                }
                Command::Close if pkt.arg1 == local_id => {
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
    pub async fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        {
            let slot = self.slot_mut(ch)?;
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
        let rx_cap = self.config.rx_cap();

        loop {
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.config.max_payload(),
            )
            .await?;
            match pkt.command {
                Command::Write if pkt.arg1 == local_id => {
                    let payload_len = pkt.data.len();
                    self.send_okay(local_id, remote_id, payload_len).await?;

                    let n = buf.len().min(pkt.data.len());
                    buf[..n].copy_from_slice(&pkt.data[..n]);
                    if n < pkt.data.len() {
                        if let Some(slot) = self.channels[ch.slot].as_mut() {
                            slot.push_rx(&pkt.data[n..], rx_cap)?;
                        }
                    }
                    return Ok(n);
                }
                Command::Close if pkt.arg1 == local_id => {
                    if let Some(slot) = self.channels[ch.slot].as_mut() {
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

        let max = (self.max_payload as usize).max(1);
        let delayed_ack = self.delayed_ack;
        let checksum = self.checksum();

        let mut offset = 0;
        while offset < data.len() {
            self.wait_ack(ch).await?;

            let mut n = (data.len() - offset).min(max);
            if delayed_ack {
                let slot = self.slot_mut(ch)?;
                let budget = slot.send_budget.max(0) as usize;
                n = n.min(budget);
                debug_assert!(n > 0, "wait_ack returned with zero budget");
            }

            let (local_id, remote_id) = self.channel_ids(ch)?;
            send_raw(
                &mut self.transport,
                &self.desync,
                Command::Write,
                local_id,
                remote_id,
                &data[offset..offset + n],
                checksum,
            )
            .await?;

            let slot = self.slot_mut(ch)?;
            if delayed_ack {
                slot.send_budget -= n as i64;
            } else {
                slot.wrte_acked = false;
            }
            offset += n;
        }

        Ok(())
    }

    /// Close a channel.
    pub async fn close_channel(
        &mut self,
        ch: ChannelId,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.desync.check()?;
        let (local_id, remote_id) = self.channel_ids(ch)?;
        let checksum = self.checksum();
        send_pkt(
            &mut self.transport,
            &self.desync,
            &Packet::close(local_id, remote_id),
            checksum,
        )
        .await?;
        self.channels[ch.slot] = None;
        Ok(())
    }

    /// Read from a channel, returning early if `interrupt` resolves first.
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
        self.desync.check()?;
        let cancel_safe = self.transport.read_cancel_safe();
        {
            let slot = self.slot_mut(ch)?;
            if !slot.rx_buf.is_empty() {
                let n = buf.len().min(slot.rx_buf.len());
                buf[..n].copy_from_slice(&slot.rx_buf[..n]);
                let _ = slot.rx_buf.split_to(n);
                return Ok(SelectResult::Data(n));
            }
            if slot.is_closed() {
                return Err(Error::ChannelClosed);
            }
        }

        let (local_id, remote_id) = self.channel_ids(ch)?;
        let delayed_ack = self.delayed_ack;
        let rx_cap = self.config.rx_cap();
        let checksum = self.checksum();

        let mut interrupt = core::pin::pin!(interrupt);

        loop {
            if let Some(pkt) = Packet::decode(&mut self.recv_buf, self.config.max_payload())? {
                match pkt.command {
                    Command::Write if pkt.arg1 == local_id => {
                        let payload_len = pkt.data.len();
                        send_okay_to(
                            &mut self.transport,
                            &self.desync,
                            delayed_ack,
                            local_id,
                            remote_id,
                            payload_len,
                            checksum,
                        )
                        .await?;

                        let n = buf.len().min(pkt.data.len());
                        buf[..n].copy_from_slice(&pkt.data[..n]);
                        if n < pkt.data.len() {
                            if let Some(slot) = self.channels[ch.slot].as_mut() {
                                slot.push_rx(&pkt.data[n..], rx_cap)?;
                            }
                        }
                        return Ok(SelectResult::Data(n));
                    }
                    Command::Close if pkt.arg1 == local_id => {
                        if let Some(slot) = self.channels[ch.slot].as_mut() {
                            slot.apply_close();
                        }
                        return Err(Error::ChannelClosed);
                    }
                    _ => {
                        dispatch_to(
                            &mut self.transport,
                            &self.desync,
                            &mut self.channels,
                            delayed_ack,
                            rx_cap,
                            checksum,
                            pkt,
                        )
                        .await?;
                        continue;
                    }
                }
            }

            {
                enum Wakeup<O> {
                    Read(usize),
                    Interrupt(O),
                }

                let want = Packet::missing(&self.recv_buf).max(MIN_READ);
                let this = &mut *self;
                let mut staged = Staged::new(&mut this.recv_buf, want);
                let transport = &mut this.transport;

                let wakeup = if cancel_safe {
                    let mut read_fut = core::pin::pin!(transport.read(staged.spare()));

                    core::future::poll_fn(|cx| {
                        if let Poll::Ready(val) = interrupt.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Wakeup::Interrupt(val)));
                        }
                        match read_fut.as_mut().poll(cx) {
                            Poll::Ready(Ok(0)) => Poll::Ready(Err(Error::UnexpectedEof)),
                            Poll::Ready(Ok(n)) => Poll::Ready(Ok(Wakeup::Read(n))),
                            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(e))),
                            Poll::Pending => Poll::Pending,
                        }
                    })
                    .await?
                } else {
                    // The transport loses whatever it has already been
                    // handed if a read is dropped, so `interrupt` only
                    // gets its answer between reads: due now, or once
                    // this read has run its course.
                    let due =
                        core::future::poll_fn(|cx| Poll::Ready(interrupt.as_mut().poll(cx))).await;
                    if let Poll::Ready(val) = due {
                        return Ok(SelectResult::Interrupted(val));
                    }
                    match transport.read(staged.spare()).await {
                        Ok(0) => return Err(Error::UnexpectedEof),
                        Ok(n) => Wakeup::Read(n),
                        Err(e) => return Err(Error::Io(e)),
                    }
                };
                match wakeup {
                    // `staged` trims the untouched tail as it drops, in
                    // both arms.
                    Wakeup::Read(n) => staged.commit(n),
                    Wakeup::Interrupt(val) => return Ok(SelectResult::Interrupted(val)),
                }
            }
        }
    }

    fn next_local_id(&mut self) -> u32 {
        const RESERVED_ADB_ID: u32 = 0;
        let id = self.local_id_counter;
        self.local_id_counter = self.local_id_counter.wrapping_add(1);
        if self.local_id_counter == RESERVED_ADB_ID {
            self.local_id_counter = 1;
        }
        id
    }

    fn slot_mut(
        &mut self,
        ch: ChannelId,
    ) -> Result<&mut ChannelSlot, Error<<T as ErrorType>::Error>> {
        self.channels
            .get_mut(ch.slot)
            .and_then(|s| s.as_mut())
            .filter(|s| s.local_id == ch.local_id)
            .ok_or(Error::ChannelClosed)
    }

    pub(crate) fn channel_ids(
        &self,
        ch: ChannelId,
    ) -> Result<(u32, u32), Error<<T as ErrorType>::Error>> {
        channel_ids_of(&self.channels, ch)
    }

    async fn send_okay(
        &mut self,
        local_id: u32,
        remote_id: u32,
        wrte_len: usize,
    ) -> Result<(), Error<<T as ErrorType>::Error>> {
        let checksum = self.checksum();
        let delayed_ack = self.delayed_ack;
        send_okay_to(
            &mut self.transport,
            &self.desync,
            delayed_ack,
            local_id,
            remote_id,
            wrte_len,
            checksum,
        )
        .await
    }

    async fn dispatch(&mut self, pkt: Packet) -> Result<(), Error<<T as ErrorType>::Error>> {
        let delayed_ack = self.delayed_ack;
        let rx_cap = self.config.rx_cap();
        let checksum = self.checksum();
        dispatch_to(
            &mut self.transport,
            &self.desync,
            &mut self.channels,
            delayed_ack,
            rx_cap,
            checksum,
            pkt,
        )
        .await
    }

    async fn wait_ack(&mut self, ch: ChannelId) -> Result<(), Error<<T as ErrorType>::Error>> {
        let delayed_ack = self.delayed_ack;
        loop {
            {
                let slot = self.slot_mut(ch)?;
                if delayed_ack {
                    if slot.send_budget > 0 {
                        return Ok(());
                    }
                } else if slot.wrte_acked {
                    return Ok(());
                }
                if slot.is_closed() {
                    return Err(Error::ChannelClosed);
                }
            }

            let local_id = self.channel_ids(ch)?.0;
            let pkt = recv_pkt(
                &mut self.transport,
                &mut self.recv_buf,
                self.config.max_payload(),
            )
            .await?;

            match pkt.command {
                Command::Ready if pkt.arg1 == local_id => {
                    if let Some(slot) = self.channels[ch.slot].as_mut() {
                        slot.apply_ready(&pkt.data, delayed_ack)?;
                        if !delayed_ack {
                            return Ok(());
                        }
                    }
                }
                Command::Close if pkt.arg1 == local_id => {
                    if let Some(slot) = self.channels[ch.slot].as_mut() {
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

mod config;
mod handshake;

#[cfg(test)]
mod tests;
