//! One channel's entry in the channel table: its state, what it has
//! received and not handed out, and the flow control both ways.

#[cfg(test)]
mod tests;

use bytes::{Buf, BytesMut};

use super::ids::{ChannelIds, LocalId, RemoteId};
use super::negotiated::{AckMode, RxPolicy};
use super::send_queue::SendQueue;
use crate::error::{Error, ProtocolError, RxOverflow};

/// AOSP's adbd always sends the 4-byte credit; when a peer omits it,
/// the operation that received the packet fails with
/// [`ProtocolError::ShortReadyPayload`] — deliberate strictness over
/// guessing a budget.
pub(crate) fn parse_ready_credit(payload: &[u8]) -> Result<u32, ProtocolError> {
    if payload.len() >= 4 {
        Ok(u32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    } else {
        Err(ProtocolError::ShortReadyPayload)
    }
}

/// The OKAY a channel owes the device for data that left its buffer,
/// or never had to stay in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingAck {
    /// The channel the OKAY is for.
    pub(crate) ids: ChannelIds,
    /// Bytes it acknowledges: the credit it hands back under delayed
    /// ACK, and nothing the device reads otherwise.
    pub(crate) len: usize,
}

/// Whether an inbound WRTE is acknowledged now or once it is read.
pub(crate) enum AckDecision {
    Now(PendingAck),
    Hold,
}

/// What breaks one channel without breaking the connection: the packet
/// was read whole, so the stream stays in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelFault {
    /// A WRTE did not fit the channel's receive buffer.
    RxOverflow,
    /// A READY the channel cannot take, such as one without its
    /// delayed-ACK credit.
    Protocol(ProtocolError),
}

impl ChannelFault {
    pub fn error<E>(self) -> Error<E> {
        match self {
            Self::RxOverflow => Error::ChannelRxOverflow,
            Self::Protocol(e) => Error::Protocol(e),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelState {
    Opening,
    Open,
    Closed,
}

/// One channel's entry in the table: its ids, its state, what it has
/// received and not handed out, and what it may still send.
pub(crate) struct ChannelSlot {
    local: LocalId,
    /// The device's end, named by the READY that opened the channel:
    /// `None` while our OPEN waits for an answer, and for good if the
    /// device refused it.
    remote: Option<RemoteId>,
    state: ChannelState,
    /// How the channel acknowledges and how much it may buffer.
    policy: RxPolicy,
    rx_buf: BytesMut,
    /// Without delayed ACK: whether our last WRTE has its OKAY, which
    /// is what lets the next one go.
    wrte_acked: bool,
    /// With delayed ACK: the credit left to send on.
    send_budget: i64,
    /// Bytes received for this channel that the peer has not been
    /// acknowledged for yet — the backpressure the device feels.
    unacked: usize,
    /// How much of `rx_buf`, from its head, has its OKAY settled and is
    /// yet to be taken. That OKAY lets the device send as much again,
    /// which can land first, so these bytes no longer count against
    /// what it may send; and what lands behind them owes an OKAY of its
    /// own, so a take stops here.
    settled: usize,
    /// The order concurrent writers take the budget in.
    send_queue: SendQueue,
    /// What broke this channel, once [`fail`](Self::fail) closed it for
    /// that: its calls then fail with this rather than `ChannelClosed`.
    failed: Option<ChannelFault>,
}

impl ChannelSlot {
    /// A channel we opened as `local`, waiting for the device's READY.
    pub fn opening(local: LocalId, policy: RxPolicy) -> Self {
        Self {
            local,
            remote: None,
            state: ChannelState::Opening,
            policy,
            rx_buf: BytesMut::new(),
            wrte_acked: true,
            send_budget: 0,
            unacked: 0,
            settled: 0,
            send_queue: SendQueue::default(),
            failed: None,
        }
    }

    /// A channel the device opened, which we took: open from the start.
    /// `credit` is OPEN's `arg1`, the device's receive credit, and so
    /// our send budget under delayed ACK.
    pub fn accepted(ids: ChannelIds, credit: u32, policy: RxPolicy) -> Self {
        let mut slot = Self::opening(ids.local, policy);
        slot.remote = Some(ids.remote);
        slot.state = ChannelState::Open;
        if policy.ack == AckMode::Delayed {
            slot.send_budget = i64::from(credit);
        }
        slot
    }

    /// Our end of the channel.
    pub fn local(&self) -> LocalId {
        self.local
    }

    /// Where the channel stands.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// Whether a fault closed the channel, its CLSE sent with it.
    pub fn is_failed(&self) -> bool {
        self.failed.is_some()
    }

    /// Both ends of the channel, once the device named its own.
    pub fn ids(&self) -> Option<ChannelIds> {
        Some(ChannelIds {
            local: self.local,
            remote: self.remote?,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.state == ChannelState::Closed
    }

    /// The error a call on this channel fails with once it is closed.
    pub fn closed_error<E>(&self) -> Error<E> {
        self.failed
            .map_or(Error::ChannelClosed, ChannelFault::error)
    }

    pub fn accept_open_ready(
        &mut self,
        remote: RemoteId,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        // Parsed first: a READY the slot cannot take leaves it as it
        // was, still opening, rather than open with no budget.
        if self.policy.ack == AckMode::Delayed {
            self.send_budget = parse_ready_credit(payload)? as i64;
        }
        self.remote = Some(remote);
        self.state = ChannelState::Open;
        Ok(())
    }

    pub fn apply_ready(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        match self.policy.ack {
            AckMode::Delayed => self.send_budget += parse_ready_credit(payload)? as i64,
            AckMode::Classic => self.wrte_acked = true,
        }
        Ok(())
    }

    /// Take an inbound WRTE and say whether to acknowledge it now.
    ///
    /// Acknowledging re-opens the sender's window, so doing it on
    /// arrival lets the device keep writing to a channel the application
    /// never reads, and the buffer grows without bound.
    ///
    /// With delayed ACK the answer is always "later": credit is returned
    /// as the application consumes bytes, and the budget we advertised
    /// bounds what can pile up. Without it the window is a single
    /// packet, so waiting for the read on every packet would turn the
    /// channel into a ping-pong: the OKAY goes out at once while little
    /// is buffered, and is held back once the watermark's worth of bytes
    /// is waiting to be read.
    pub fn apply_write(&mut self, payload: &[u8]) -> Result<AckDecision, RxOverflow> {
        self.push_rx(payload)?;
        self.unacked = self.unacked.saturating_add(payload.len());
        if self.policy.ack == AckMode::Classic && self.held() < self.policy.watermark {
            if let Some(ack) = self.ack(payload.len()) {
                self.unacked = 0;
                return Ok(AckDecision::Now(ack));
            }
        }
        Ok(AckDecision::Hold)
    }

    /// Say what to acknowledge for a freshly arrived packet of `taken`
    /// bytes that went straight to the caller, all of it. A packet with
    /// any part left over belongs in [`apply_write`](Self::apply_write).
    pub fn deliver(&mut self, taken: usize) -> Option<PendingAck> {
        if self.policy.ack == AckMode::Delayed {
            return self.ack(taken).filter(|ack| ack.len > 0);
        }
        if self.rx_buf.len() >= self.policy.watermark {
            return None;
        }
        let ack = self.ack(self.unacked)?;
        self.unacked = 0;
        Some(ack)
    }

    /// The OKAY for `len` bytes on this channel. `None` until the
    /// device has named its end: the acknowledgement waits until there
    /// is one to address it to.
    fn ack(&self, len: usize) -> Option<PendingAck> {
        Some(PendingAck {
            ids: self.ids()?,
            len,
        })
    }

    /// How much taking `n` bytes acknowledges, `remaining` being what
    /// the buffer holds once they are gone. With delayed ACK, the bytes
    /// taken; without it, everything held back, once the buffer is
    /// below the watermark again.
    fn ack_len(&self, n: usize, remaining: usize) -> Option<usize> {
        if self.unacked == 0 {
            return None;
        }
        match self.policy.ack {
            AckMode::Delayed => {
                let len = n.min(self.unacked);
                (len > 0).then_some(len)
            }
            AckMode::Classic => (remaining < self.policy.watermark).then_some(self.unacked),
        }
    }

    /// Whether [`take_buffered`](Self::take_buffered) has bytes to hand
    /// out. Nothing is taken before the device has named its end: what
    /// it wrote ahead of the READY to our OPEN stays buffered, counted
    /// as unacknowledged, until that READY gives its OKAY somewhere to
    /// go. A channel closed before it ever opened has nothing to hand
    /// out.
    pub fn has_data(&self) -> bool {
        self.remote.is_some() && !self.rx_buf.is_empty()
    }

    /// Settle what taking up to `want` buffered bytes owes the device,
    /// and return the OKAY to send. `None` with nothing to settle, or
    /// with bytes still settled, which go first.
    ///
    /// The bytes themselves stay until
    /// [`take_buffered`](Self::take_buffered). The OKAY goes between the
    /// two, so a call dropped during that write has taken nothing, and
    /// what it left stays readable with no gap in it.
    pub fn settle_take(&mut self, want: usize) -> Option<PendingAck> {
        let ids = self.ids().filter(|_| self.settled == 0)?;
        let n = want.min(self.rx_buf.len());
        let len = self.ack_len(n, self.rx_buf.len() - n)?;
        self.unacked -= len;
        self.settled = n;
        Some(PendingAck { ids, len })
    }

    /// Copy buffered bytes into `buf`: those settled if there are any,
    /// and nothing behind them. `None` while an open channel has nothing
    /// to hand out; once a closed one is drained,
    /// [`Error::ChannelClosed`] or the fault that closed it. What this
    /// owes the device is for [`settle_take`](Self::settle_take).
    pub fn take_buffered<E>(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error<E>> {
        if !self.has_data() {
            return if self.is_closed() {
                Err(self.closed_error())
            } else {
                Ok(None)
            };
        }
        let ready = match self.settled {
            0 => self.rx_buf.len(),
            settled => settled,
        };
        let n = buf.len().min(ready);
        buf[..n].copy_from_slice(&self.rx_buf[..n]);
        self.rx_buf.advance(n);
        self.settled -= n.min(self.settled);
        Ok(Some(n))
    }

    /// What `rx_buf` holds that is not on its way out.
    fn held(&self) -> usize {
        self.rx_buf.len() - self.settled
    }

    fn push_rx(&mut self, payload: &[u8]) -> Result<(), RxOverflow> {
        if self.held().saturating_add(payload.len()) > self.policy.rx_cap {
            return Err(RxOverflow);
        }
        self.rx_buf.extend_from_slice(payload);
        Ok(())
    }

    /// The device closed the channel. It has no socket left to take an
    /// OKAY, so nothing it sent is owed one from here on, however much
    /// of it is still to be read.
    pub fn apply_close(&mut self) {
        self.state = ChannelState::Closed;
        self.unacked = 0;
    }

    /// How much may be sent now: `None` while we wait for the device's
    /// OKAY; otherwise the credit left under delayed ACK, and without
    /// it no bound but the packet size.
    pub fn budget(&self) -> Option<usize> {
        match self.policy.ack {
            AckMode::Delayed => (self.send_budget > 0).then_some(self.send_budget as usize),
            AckMode::Classic => self.wrte_acked.then_some(usize::MAX),
        }
    }

    /// Account for `n` bytes sent: they come off the credit, or, without
    /// delayed ACK, the next WRTE waits for this one's OKAY.
    pub fn spend(&mut self, n: usize) {
        match self.policy.ack {
            AckMode::Delayed => self.send_budget -= n as i64,
            AckMode::Classic => self.wrte_acked = false,
        }
    }
}

/// What only the split halves ask of a slot: credit spent ahead of the
/// send it pays for, a channel closed for a fault, and writers taking
/// turns.
#[cfg_attr(not(feature = "split"), allow(dead_code))]
impl ChannelSlot {
    /// Whether taking up to `want` buffered bytes now would owe the
    /// device an OKAY — what [`settle_take`](Self::settle_take) would
    /// answer, without settling anything.
    pub fn take_acks(&self, want: usize) -> bool {
        if !self.has_data() || self.settled > 0 {
            return false;
        }
        let n = want.min(self.rx_buf.len());
        self.ack_len(n, self.rx_buf.len() - n).is_some()
    }

    /// Spend up to `want` bytes of [`budget`](Self::budget) ahead of
    /// sending them, if there is any.
    pub fn try_reserve_send(&mut self, want: usize) -> Option<usize> {
        let n = self.budget()?.min(want);
        self.spend(n);
        Some(n)
    }

    /// Give back `n` bytes reserved for a send that never went out.
    pub fn refund(&mut self, n: usize) {
        match self.policy.ack {
            AckMode::Delayed => self.send_budget += n as i64,
            AckMode::Classic => self.wrte_acked = true,
        }
    }

    /// Close this channel for `fault`. Nothing is acknowledged after
    /// it, so the device gets no OKAY for a channel we are closing.
    pub fn fail(&mut self, fault: ChannelFault) {
        self.failed = Some(fault);
        self.state = ChannelState::Closed;
        self.unacked = 0;
    }

    /// The queue the channel's writers wait their turn in.
    pub fn send_queue(&mut self) -> &mut SendQueue {
        &mut self.send_queue
    }
}

#[cfg(test)]
impl ChannelSlot {
    /// Bytes waiting to be read.
    pub fn buffered(&self) -> usize {
        self.rx_buf.len()
    }

    /// Bytes the device has had no OKAY for yet.
    pub fn unacked(&self) -> usize {
        self.unacked
    }
}
