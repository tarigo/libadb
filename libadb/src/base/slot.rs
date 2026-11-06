#[cfg(test)]
mod tests;

use bytes::{Buf, BytesMut};

use super::ids::{ChannelIds, LocalId, RemoteId};
use super::negotiated::{AckMode, RxPolicy};
use super::send_queue::SendQueue;
use crate::error::{Error, ProtocolError, RxOverflow};

pub(crate) fn parse_ready_credit(payload: &[u8]) -> Result<u32, ProtocolError> {
    if payload.len() >= 4 {
        Ok(u32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    } else {
        Err(ProtocolError::ShortReadyPayload)
    }
}

fn credit_of(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingAck {
    pub(crate) ids: ChannelIds,
    pub(crate) len: usize,
}

pub(crate) enum AckDecision {
    Now(PendingAck),
    Hold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelFault {
    RxOverflow,
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

pub(crate) struct ChannelSlot {
    local: LocalId,
    remote: Option<RemoteId>,
    state: ChannelState,
    policy: RxPolicy,
    rx_buf: BytesMut,
    wrte_acked: bool,
    send_budget: i64,
    unacked: usize,
    settled: usize,
    send_queue: SendQueue,
    failed: Option<ChannelFault>,
}

impl ChannelSlot {
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

    pub fn accepted(ids: ChannelIds, credit: u32, policy: RxPolicy) -> Self {
        let mut slot = Self::opening(ids.local, policy);
        slot.remote = Some(ids.remote);
        slot.state = ChannelState::Open;
        if policy.ack == AckMode::Delayed {
            slot.send_budget = i64::from(credit);
        }
        slot
    }

    pub fn local(&self) -> LocalId {
        self.local
    }

    pub fn state(&self) -> ChannelState {
        self.state
    }

    pub fn is_failed(&self) -> bool {
        self.failed.is_some()
    }

    pub fn ids(&self) -> Option<ChannelIds> {
        Some(ChannelIds {
            local: self.local,
            remote: self.remote?,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.state == ChannelState::Closed
    }

    pub fn closed_error<E>(&self) -> Error<E> {
        self.failed
            .map_or(Error::ChannelClosed, ChannelFault::error)
    }

    pub fn accept_open_ready(
        &mut self,
        remote: RemoteId,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.policy.ack == AckMode::Delayed {
            self.send_budget = parse_ready_credit(payload)? as i64;
        }
        self.remote = Some(remote);
        self.state = ChannelState::Open;
        Ok(())
    }

    pub fn apply_ready(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        match self.policy.ack {
            AckMode::Delayed => {
                let credit = i64::from(parse_ready_credit(payload)?);
                self.send_budget = self.send_budget.saturating_add(credit);
            }
            AckMode::Classic => self.wrte_acked = true,
        }
        Ok(())
    }

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

    fn ack(&self, len: usize) -> Option<PendingAck> {
        Some(PendingAck {
            ids: self.ids()?,
            len,
        })
    }

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

    pub fn has_data(&self) -> bool {
        self.remote.is_some() && !self.rx_buf.is_empty()
    }

    pub fn settle_take(&mut self, want: usize) -> Option<PendingAck> {
        let ids = self.ids().filter(|_| self.settled == 0)?;
        let n = want.min(self.rx_buf.len());
        let len = self.ack_len(n, self.rx_buf.len() - n)?;
        self.unacked -= len;
        self.settled = n;
        Some(PendingAck { ids, len })
    }

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

    pub fn apply_close(&mut self) {
        self.state = ChannelState::Closed;
        self.unacked = 0;
    }

    pub fn budget(&self) -> Option<usize> {
        match self.policy.ack {
            AckMode::Delayed => (self.send_budget > 0)
                .then(|| usize::try_from(self.send_budget).unwrap_or(usize::MAX)),
            AckMode::Classic => self.wrte_acked.then_some(usize::MAX),
        }
    }

    pub fn spend(&mut self, n: usize) {
        match self.policy.ack {
            AckMode::Delayed => self.send_budget = self.send_budget.saturating_sub(credit_of(n)),
            AckMode::Classic => self.wrte_acked = false,
        }
    }
}

#[cfg_attr(not(feature = "split"), allow(dead_code))]
impl ChannelSlot {
    pub fn take_acks(&self, want: usize) -> bool {
        if !self.has_data() || self.settled > 0 {
            return false;
        }
        let n = want.min(self.rx_buf.len());
        self.ack_len(n, self.rx_buf.len() - n).is_some()
    }

    pub fn try_reserve_send(&mut self, want: usize) -> Option<usize> {
        let n = self.budget()?.min(want);
        self.spend(n);
        Some(n)
    }

    pub fn refund(&mut self, n: usize) {
        match self.policy.ack {
            AckMode::Delayed => self.send_budget = self.send_budget.saturating_add(credit_of(n)),
            AckMode::Classic => self.wrte_acked = true,
        }
    }

    pub fn fail(&mut self, fault: ChannelFault) {
        self.failed = Some(fault);
        self.state = ChannelState::Closed;
        self.unacked = 0;
    }

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
