//! [`Writer`], the cloneable half every channel operation can go
//! through, and the close path it shares with the [`Reader`].

use alloc::sync::Arc;
use core::convert::Infallible;
use core::future::{poll_fn, Future};
use core::pin::{pin, Pin};
use core::sync::atomic::Ordering;
use core::task::Poll;
use embedded_io::ErrorType;
use embedded_io_async::Write;
use event_listener::EventListener;

use super::shared::{CreditGuard, Owed, QueueGuard, Shared, SlotGuard};
use super::IncomingListener;
use crate::base::channel::{ChannelId, SelectResult};
use crate::base::connection::ConnectionConfig;
use crate::base::ids::ChannelIds;
use crate::base::negotiated::Negotiated;
use crate::base::protocol::command::Command;
use crate::base::slot::ChannelState;
use crate::base::wire::send_raw;
use crate::device_banner::DeviceBanner;
use crate::error::Error;

#[cfg(doc)]
use super::Reader;

/// Write half of a split [`Connection`](crate::Connection).
///
/// Cheaply cloneable (an `Arc` bump). Methods take `&self`, so a single
/// `Writer` can be shared across threads with no additional wrapping.
pub struct Writer<WH>
where
    WH: Write,
{
    pub(super) shared: Arc<Shared<WH>>,
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
    pub fn device_banner(&self) -> &[u8] {
        self.shared.negotiated.device_banner.raw()
    }

    /// Parsed device banner from the CNXN handshake.
    ///
    /// Lock-free connection metadata — available even while the
    /// [`Reader`] is blocked in a read on another thread.
    pub fn device_banner_parsed(&self) -> &DeviceBanner {
        &self.shared.negotiated.device_banner
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
    /// accept after all, the device gets a CLSE, at the latest with the
    /// next packet `run` receives or the next write, open or close on
    /// the connection. So the device's end does not stay open for long,
    /// unless the [`Reader`] is gone and nothing reads the READY.
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
            self.shared.check_in_step()?;
            let listener = signal.listen();
            {
                let chs = self.shared.lock_channels();
                match chs.get(ch) {
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
    /// [`Error::ChannelClosed`] once its buffered data is read. For how
    /// a read fails on a failing connection, see
    /// [What arrived stays readable](crate::split#what-arrived-stays-readable).
    ///
    /// Cancellation-safe while it waits, for data or for the write half
    /// an OKAY needs: nothing has been taken then, and the data stays
    /// buffered for the next call. Dropping it while that OKAY is
    /// written has taken nothing either, but
    /// [abandons the packet](crate::split#dropping-a-call).
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
    /// arrival order: a writer looping back for its next chunk queues
    /// behind the ones already waiting.
    ///
    /// The bytes of one call go out in order; concurrent calls on the
    /// same channel interleave at chunk granularity in unspecified
    /// order, like unsynchronized writes to one socket. A caller that
    /// needs whole messages on the wire serializes the calls itself,
    /// as the FFI shell does around each frame.
    ///
    /// **Not cancellation-safe**: see
    /// [Dropping a call](crate::split#dropping-a-call). Credit reserved
    /// and not yet sent is refunded when the future is dropped.
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

    /// Whether the writers on `ch` have nothing left to do but wait for
    /// the device: one is parked for credit the channel does not have,
    /// and none is still sending.
    ///
    /// For a caller with no task to give [`Reader::run`], to decide when
    /// a pending [`write_channel`](Self::write_channel) needs packets
    /// taken off the connection with [`Reader::dispatch_one`]. That a
    /// write is pending says little: on USB one is pending through every
    /// transfer, and a read begun then could wait for a packet that
    /// never comes, since the device may owe nothing yet.
    ///
    /// A writer still sending answers `false` even with another parked
    /// behind it: its future has to be polled, not left for a read to
    /// finish.
    ///
    /// A closed or freed channel answers `false`: its writers have been
    /// woken to fail. A `true` lasts until the next packet is dispatched,
    /// so a caller about to read asks once it alone reads the connection.
    pub fn waits_for_credit(&self, ch: ChannelId) -> bool {
        let mut chs = self.shared.lock_channels();
        let Some(slot) = chs.get_mut(ch) else {
            return false;
        };
        if slot.is_closed() || slot.budget().is_some() {
            return false;
        }
        let queue = slot.send_queue();
        !queue.is_empty() && !queue.is_sending()
    }

    /// Release the channel slot and send CLSE. Any cloned `Writer`
    /// parked on this channel observes `ChannelClosed` and unblocks,
    /// whether or not the CLSE gets out.
    ///
    /// The CLSE is [owed](crate::split#what-the-device-is-owed) from the
    /// moment the slot goes. With the device gone or the stream over
    /// this returns `Ok` without it. A write that fails any other way
    /// comes back as the error, with the connection desynchronized. A
    /// connection already desynchronized fails with
    /// [`Error::Desynchronized`] and frees nothing: no call that wants a
    /// slot gets anywhere on it.
    ///
    /// Safe to drop while it waits for the write half: the next write,
    /// open, close or receive sends the CLSE. Dropping it during the
    /// write [abandons the packet](crate::split#dropping-a-call).
    ///
    /// A concurrent [`Reader::read_channel`] on the same channel is not
    /// woken: see
    /// [Closing while a read waits](crate::split#closing-while-a-read-waits).
    pub async fn close_channel(
        &self,
        ch: ChannelId,
    ) -> Result<(), Error<<WH as ErrorType>::Error>> {
        close_channel_via(&self.shared, ch).await
    }

    fn channel_ids(&self, ch: ChannelId) -> Result<ChannelIds, Error<<WH as ErrorType>::Error>> {
        self.shared.lock_channels().ids(ch)
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
            let Some(slot) = chs.get_mut(ch) else {
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
        let Some(slot) = chs.get_mut(ch) else {
            return Some(Err(Error::ChannelClosed));
        };
        if slot.is_closed() {
            return Some(Err(slot.closed_error()));
        }
        if slot.send_queue().turn() != place {
            return None;
        }
        slot.try_reserve_send(want).map(|n| {
            slot.send_queue().serve();
            Ok((n, slot.budget().is_some()))
        })
    }
}

/// Free `ch`'s slot, wake whoever waits on it, then owe its CLSE and pay
/// that: the close path shared by [`Writer::close_channel`] and
/// [`Reader::close_channel`].
pub(super) async fn close_channel_via<WH>(
    shared: &Shared<WH>,
    ch: ChannelId,
) -> Result<(), Error<<WH as ErrorType>::Error>>
where
    WH: Write,
{
    shared.desync.check()?;
    let ids = {
        let mut chs = shared.lock_channels();
        let ids = chs.ids(ch)?;
        chs.free(ch);
        ids
    };
    shared.signals[ch.slot].wake();
    shared.owe(Owed::Close(ids));
    match shared
        .until(Shared::clse_called_off, shared.lock_write())
        .await
    {
        Some(paid) => paid.map(drop),
        None => shared.check_close(),
    }
}
