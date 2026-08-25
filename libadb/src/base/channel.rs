use bytes::BytesMut;
use core::future::Future;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::connection::{
    Connection, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_FEATURES, DEFAULT_MAX_PROPERTIES,
};
use super::error::{Error, ProtocolError, RxOverflow};
use super::protocol::command::Command;
use super::protocol::Packet;

pub(crate) fn parse_ready_credit(payload: &[u8]) -> Result<u32, ProtocolError> {
    if payload.len() >= 4 {
        Ok(u32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    } else {
        Err(ProtocolError::ShortReadyPayload)
    }
}

#[allow(dead_code)] // `idx` only read by split::Reader::dispatch
pub(crate) enum DispatchOutcome {
    AckWrite {
        local_id: u32,
        remote_id: u32,
        len: usize,
    },
    SlotUpdated {
        idx: usize,
    },
    Unmatched,
}

/// `rx_cap` bounds how much unread data a single channel may accumulate;
/// a WRTE that would push it past the cap fails with
/// [`Error::ChannelRxOverflow`] instead of growing the buffer.
pub(crate) fn dispatch_packet<E>(
    channels: &mut [Option<ChannelSlot>],
    pkt: &Packet,
    delayed_ack: bool,
    rx_cap: usize,
) -> Result<DispatchOutcome, Error<E>> {
    for (idx, slot_opt) in channels.iter_mut().enumerate() {
        let Some(slot) = slot_opt else { continue };
        match pkt.command {
            Command::Write if pkt.arg1 == slot.local_id => {
                let (local_id, remote_id, len) = slot.apply_write(&pkt.data, rx_cap)?;
                return Ok(DispatchOutcome::AckWrite {
                    local_id,
                    remote_id,
                    len,
                });
            }
            Command::Ready if pkt.arg1 == slot.local_id => {
                slot.apply_ready(&pkt.data, delayed_ack)?;
                return Ok(DispatchOutcome::SlotUpdated { idx });
            }
            Command::Close if pkt.arg1 == slot.local_id => {
                slot.apply_close();
                return Ok(DispatchOutcome::SlotUpdated { idx });
            }
            _ => {}
        }
    }
    Ok(DispatchOutcome::Unmatched)
}

/// Result of [`Channel::select`] / [`Connection::select_channel`].
#[derive(Debug)]
pub enum SelectResult<T> {
    /// The channel produced data — value is the number of bytes read.
    Data(usize),
    /// The interrupt future completed with this value before channel data
    /// arrived. The channel state is unchanged and the next read will
    /// pick up where this one left off.
    Interrupted(T),
}

/// Opaque handle to an open ADB channel.
///
/// Used with [`Connection::open_channel`], [`read_channel`](Connection::read_channel),
/// [`write_channel`](Connection::write_channel), [`close_channel`](Connection::close_channel).
/// A stale handle from a closed channel never aliases a later reopened
/// one — it returns [`Error::ChannelClosed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId {
    pub(crate) slot: usize,
    pub(crate) local_id: u32,
}

impl ChannelId {
    /// Build a `ChannelId` from raw `(slot, local_id)`. Intended for
    /// FFI bridges that round-trip a handle through an opaque integer;
    /// ordinary Rust callers should use the `ChannelId` returned by
    /// [`Connection::open_channel`] directly.
    pub fn from_raw(slot: usize, local_id: u32) -> Self {
        Self { slot, local_id }
    }

    /// Slot index in the connection's channel table.
    pub fn slot(self) -> usize {
        self.slot
    }

    /// ADB wire `local_id` for this channel — unique per OPEN.
    pub fn local_id(self) -> u32 {
        self.local_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelState {
    Opening,
    Open,
    Closed,
}

pub(crate) struct ChannelSlot {
    pub local_id: u32,
    pub remote_id: u32,
    pub state: ChannelState,
    pub rx_buf: BytesMut,
    pub wrte_acked: bool,
    pub send_budget: i64,
}

impl ChannelSlot {
    pub fn new(local_id: u32) -> Self {
        Self {
            local_id,
            remote_id: 0,
            state: ChannelState::Opening,
            rx_buf: BytesMut::new(),
            wrte_acked: true,
            send_budget: 0,
        }
    }

    pub fn channel_ids(&self) -> (u32, u32) {
        (self.local_id, self.remote_id)
    }

    pub fn is_closed(&self) -> bool {
        self.state == ChannelState::Closed
    }

    pub fn accept_open_ready(
        &mut self,
        remote_id: u32,
        payload: &[u8],
        delayed_ack: bool,
    ) -> Result<(), ProtocolError> {
        self.remote_id = remote_id;
        self.state = ChannelState::Open;
        if delayed_ack {
            self.send_budget = parse_ready_credit(payload)? as i64;
        }
        Ok(())
    }

    pub fn apply_ready(&mut self, payload: &[u8], delayed_ack: bool) -> Result<(), ProtocolError> {
        if delayed_ack {
            self.send_budget += parse_ready_credit(payload)? as i64;
        } else {
            self.wrte_acked = true;
        }
        Ok(())
    }

    pub fn apply_write(
        &mut self,
        payload: &[u8],
        cap: usize,
    ) -> Result<(u32, u32, usize), RxOverflow> {
        self.push_rx(payload, cap)?;
        Ok((self.local_id, self.remote_id, payload.len()))
    }

    pub fn push_rx(&mut self, payload: &[u8], cap: usize) -> Result<(), RxOverflow> {
        if self.rx_buf.len().saturating_add(payload.len()) > cap {
            return Err(RxOverflow);
        }
        self.rx_buf.extend_from_slice(payload);
        Ok(())
    }

    pub fn apply_close(&mut self) {
        self.state = ChannelState::Closed;
    }

    #[allow(dead_code)] // used only by split::Writer
    pub fn try_reserve_send(&mut self, want: usize, delayed_ack: bool) -> Option<usize> {
        if delayed_ack {
            if self.send_budget > 0 {
                let n = (self.send_budget as usize).min(want);
                self.send_budget -= n as i64;
                return Some(n);
            }
        } else if self.wrte_acked {
            self.wrte_acked = false;
            return Some(want);
        }
        None
    }

    #[allow(dead_code)] // used only by split::Writer's CreditGuard
    pub fn refund(&mut self, n: usize, delayed_ack: bool) {
        if delayed_ack {
            self.send_budget += n as i64;
        } else {
            self.wrte_acked = true;
        }
    }
}

pub(crate) fn channel_ids_of<E>(
    channels: &[Option<ChannelSlot>],
    ch: ChannelId,
) -> Result<(u32, u32), Error<E>> {
    channels
        .get(ch.slot)
        .and_then(|s| s.as_ref())
        .filter(|s| s.local_id == ch.local_id)
        .map(ChannelSlot::channel_ids)
        .ok_or(Error::ChannelClosed)
}

#[allow(dead_code)] // used only by split::{CreditGuard, Reader, Writer}
pub(crate) fn slot_for_mut(
    channels: &mut [Option<ChannelSlot>],
    ch: ChannelId,
) -> Option<&mut ChannelSlot> {
    channels
        .get_mut(ch.slot)
        .and_then(|s| s.as_mut())
        .filter(|s| s.local_id == ch.local_id)
}

/// An open ADB channel tied to a [`Connection`].
///
/// Provides [`read`](Self::read), [`write`](Self::write), and
/// [`close`](Self::close) methods.  Created by [`Connection::open`].
///
/// Because `Channel` holds a mutable borrow on the connection,
/// only one `Channel` can be active at a time.  For concurrent access to
/// multiple channels, use the [`ChannelId`]-based methods on
/// [`Connection`] directly ([`open_channel`](Connection::open_channel),
/// [`read_channel`](Connection::read_channel), etc.).
pub struct Channel<
    'a,
    T,
    const MAX_CHANNELS: usize = DEFAULT_MAX_CHANNELS,
    const MAX_PROPERTIES: usize = DEFAULT_MAX_PROPERTIES,
    const MAX_FEATURES: usize = DEFAULT_MAX_FEATURES,
> where
    T: Read + Write,
{
    pub(crate) conn: &'a mut Connection<T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>,
    pub(crate) id: ChannelId,
}

impl<'a, T, const MAX_CHANNELS: usize, const MAX_PROPERTIES: usize, const MAX_FEATURES: usize>
    Channel<'a, T, MAX_CHANNELS, MAX_PROPERTIES, MAX_FEATURES>
where
    T: Read + Write,
{
    /// Read data from the channel into `buf`.
    ///
    /// Returns the number of bytes read. If data was already buffered
    /// (from a previous WRTE) the call returns immediately. Otherwise it
    /// blocks until a WRTE arrives for this channel, buffering messages
    /// for other channels in the meantime.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<<T as ErrorType>::Error>> {
        self.conn.read_channel(self.id, buf).await
    }

    /// Write data to the channel.
    ///
    /// Data is split into `max_payload`-sized chunks with appropriate
    /// flow-control (OKAY acknowledgement in legacy mode, credit-based
    /// budgeting in delayed ACK mode).
    pub async fn write(&mut self, data: &[u8]) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.conn.write_channel(self.id, data).await
    }

    /// Read from the channel, but return early if `interrupt` resolves first.
    ///
    /// This is the primary way to combine channel reads with other async
    /// event sources (e.g. stdin, signals) without raw packet manipulation.
    /// If `interrupt` wins, the channel state is unchanged and the next
    /// call resumes normally.
    ///
    /// How quickly `interrupt` can win depends on the transport. Over
    /// TCP it is raced against the read itself, so a pending read is
    /// dropped the moment the interrupt is due. A transport that would
    /// lose data that way — USB, where cancelling a bulk transfer
    /// discards what the device already wrote into it — has the
    /// interrupt checked between reads instead, so it takes effect once
    /// the read in flight has finished. See
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
    ///
    /// ```ignore
    /// loop {
    ///     match ch.select(&mut buf, stdin_rx.recv()).await? {
    ///         SelectResult::Data(n) => { /* handle buf[..n] */ }
    ///         SelectResult::Interrupted(input) => {
    ///             ch.write(&input).await?;
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn select<F: Future>(
        &mut self,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<<T as ErrorType>::Error>>
    where
        T: crate::transport::ReadCancelSafety,
    {
        self.conn.select_channel(self.id, buf, interrupt).await
    }

    /// Close the channel, sending CLSE to the device and freeing the slot.
    ///
    /// Consumes the `Channel`.
    pub async fn close(self) -> Result<(), Error<<T as ErrorType>::Error>> {
        self.conn.close_channel(self.id).await
    }
}
