use alloc::collections::BTreeSet;
use bytes::{Buf, Bytes, BytesMut};
use core::future::Future;

use super::error::{Error, ProtocolError, RxOverflow};
use super::ids::{ChannelIds, LocalId, RemoteId};
use super::negotiated::{AckMode, RxPolicy};
use super::protocol::command::Command;
use super::protocol::Packet;
use super::session::Session;

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

pub(crate) enum DispatchOutcome {
    /// A WRTE was buffered and has to be acknowledged now.
    AckWrite {
        #[allow(dead_code)] // read only by split::Reader, to wake readers
        idx: usize,
        ack: PendingAck,
    },
    /// An OKAY refilled the slot's send budget: one writer can proceed.
    CreditGranted {
        #[allow(dead_code)] // read only by split::Reader, to wake writers
        idx: usize,
    },
    /// A CLSE closed the slot: every waiter has to see the error.
    SlotClosed {
        #[allow(dead_code)] // read only by split::Reader, to wake writers
        idx: usize,
    },
    /// A WRTE was buffered with its acknowledgement held back until it
    /// is read.
    DataBuffered {
        #[allow(dead_code)] // read only by split::Reader, to wake readers
        idx: usize,
    },
    /// The device opened a channel toward the host (`adb reverse`).
    /// The host queues it for [`accept_incoming`] and answers READY on
    /// accept or CLSE on refusal.
    ///
    /// [`accept_incoming`]: super::connection::Connection::accept_incoming
    IncomingOpen {
        remote: RemoteId,
        /// The device's receive credit from OPEN `arg1`; our send
        /// budget once accepted, meaningful only with delayed ack.
        credit: u32,
        destination: Bytes,
    },
    /// The device gave up on an OPEN it had sent — a CLSE that names
    /// no local id. Drop the matching pending entry if still queued.
    CancelPendingOpen {
        remote: RemoteId,
    },
    /// A READY for no channel of ours: the device accepted an OPEN its
    /// opener gave up on before the answer. Answer CLSE with both ids —
    /// adbd ignores one that does not name its own — or the device's
    /// end stays open.
    StrayReady {
        ids: ChannelIds,
    },
    /// A packet broke this slot's channel alone. The slot is not
    /// closed: whoever dispatched decides what the fault costs.
    ChannelFault {
        #[allow(dead_code)] // read only by split::Reader::run, to close the channel
        idx: usize,
        #[allow(dead_code)] // read only by split::Reader::run, to close the channel
        ids: ChannelIds,
        /// The slot was waiting for the device's answer to its OPEN.
        #[allow(dead_code)] // read only by split::Reader, to fail the open
        opening: bool,
        fault: ChannelFault,
    },
    Unmatched,
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

/// A device-initiated OPEN waiting for the application's verdict.
#[derive(Debug)]
pub(crate) struct PendingOpen {
    pub remote: RemoteId,
    pub credit: u32,
    pub destination: Bytes,
}

/// A WRTE that would push a channel past its receive cap is a
/// [`ChannelFault::RxOverflow`] instead of a bigger buffer.
pub(crate) fn dispatch_packet(
    channels: &mut [Option<ChannelSlot>],
    pkt: &Packet,
) -> DispatchOutcome {
    // The handshake is over, so a device that opens it again, or asks
    // for TLS now, is out of turn. It is dropped like any packet nobody
    // claims, but said in the log, since nothing else will mention it.
    if matches!(
        pkt.command,
        Command::Connect | Command::Auth | Command::StartTls
    ) {
        log::warn!(
            "dropping {:?} from the device after the handshake",
            pkt.command
        );
        return DispatchOutcome::Unmatched;
    }
    if pkt.command == Command::Open {
        return DispatchOutcome::IncomingOpen {
            remote: RemoteId::from(pkt.arg0),
            credit: pkt.arg1,
            destination: pkt.data.clone(),
        };
    }
    if pkt.command == Command::Close && pkt.arg1 == 0 {
        // The withdrawal may have crossed our READY in flight: the
        // request is then no longer queued but an accepted slot, and
        // has to close like any remote CLSE — the cancel handlers only
        // reach requests still awaiting a verdict.
        let remote = RemoteId::from(pkt.arg0);
        if let Some(idx) = close_remote(channels, remote) {
            return DispatchOutcome::SlotClosed { idx };
        }
        return DispatchOutcome::CancelPendingOpen { remote };
    }
    let remote = RemoteId::from(pkt.arg0);
    for (idx, slot_opt) in channels.iter_mut().enumerate() {
        let Some(slot) = slot_opt else { continue };
        let ours = pkt.arg1 == slot.local.raw();
        match pkt.command {
            // A channel closed for a fault takes nothing more: data that
            // was still in flight would read as if no gap came before it.
            Command::Write | Command::Ready if ours && slot.failed.is_some() => {
                return DispatchOutcome::Unmatched;
            }
            Command::Write if ours => {
                return match slot.apply_write(&pkt.data) {
                    Ok(AckDecision::Now(ack)) => DispatchOutcome::AckWrite { idx, ack },
                    Ok(AckDecision::Hold) => DispatchOutcome::DataBuffered { idx },
                    Err(RxOverflow) => slot.fault(idx, remote, ChannelFault::RxOverflow),
                };
            }
            Command::Ready if ours => {
                let granted = if slot.state == ChannelState::Opening {
                    slot.accept_open_ready(remote, &pkt.data)
                } else {
                    slot.apply_ready(&pkt.data)
                };
                return match granted {
                    Ok(()) => DispatchOutcome::CreditGranted { idx },
                    Err(e) => slot.fault(idx, remote, ChannelFault::Protocol(e)),
                };
            }
            Command::Close if ours => {
                slot.apply_close();
                return DispatchOutcome::SlotClosed { idx };
            }
            _ => {}
        }
    }
    if pkt.command == Command::Ready && pkt.arg0 != 0 && pkt.arg1 != 0 {
        return DispatchOutcome::StrayReady {
            ids: ChannelIds {
                local: LocalId::from(pkt.arg1),
                remote,
            },
        };
    }
    DispatchOutcome::Unmatched
}

/// Close the channel whose device end is `remote`, and say which slot
/// it was in. A zero id names no end, so it closes nothing.
pub(crate) fn close_remote(
    channels: &mut [Option<ChannelSlot>],
    remote: RemoteId,
) -> Option<usize> {
    if remote.raw() == 0 {
        return None;
    }
    let idx = channels
        .iter()
        .position(|s| s.as_ref().is_some_and(|s| s.remote == Some(remote)))?;
    channels[idx].as_mut()?.apply_close();
    Some(idx)
}

/// Result of [`Channel::select`] / [`Session::select_channel`].
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
/// Used with [`Session::open_channel`], [`read_channel`](Session::read_channel),
/// [`write_channel`](Session::write_channel), [`close_channel`](Session::close_channel),
/// and the same methods on [`Connection`](crate::Connection) and the split
/// [`Writer`](crate::Writer).
/// A stale handle from a closed channel never aliases a later reopened
/// one — it returns [`Error::ChannelClosed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId {
    pub(crate) slot: usize,
    pub(crate) local: LocalId,
}

impl ChannelId {
    /// Build a `ChannelId` from raw `(slot, local_id)`. Intended for
    /// FFI bridges that round-trip a handle through an opaque integer;
    /// ordinary Rust callers should use the `ChannelId` returned by
    /// [`Session::open_channel`] directly.
    pub fn from_raw(slot: usize, local_id: u32) -> Self {
        Self {
            slot,
            local: LocalId::from(local_id),
        }
    }

    /// Slot index in the connection's channel table.
    pub fn slot(self) -> usize {
        self.slot
    }

    /// ADB wire `local_id` for this channel — unique per OPEN.
    pub fn local_id(self) -> u32 {
        self.local.raw()
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
    /// Send-queue place currently allowed to reserve credit. The queue
    /// keeps concurrent `split::Writer`s in arrival order: places are
    /// handed out by [`send_enqueue`](Self::send_enqueue) and only the
    /// holder of `send_q_head` may take budget.
    send_q_head: u64,
    send_q_tail: u64,
    /// Places whose writer left the queue unserved; skipped when the
    /// head reaches them. Bounded: a hole is only recorded below a
    /// place still occupied — a leaving tail reclaims itself and any
    /// holes adjacent to it — so cancellation churn cannot grow this
    /// past the caller's own peak of concurrent writers.
    send_q_gone: BTreeSet<u64>,
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
            send_q_head: 0,
            send_q_tail: 0,
            send_q_gone: BTreeSet::new(),
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

    /// `remote` comes from the packet: a slot still opening has none of
    /// its own yet.
    fn fault(&self, idx: usize, remote: RemoteId, fault: ChannelFault) -> DispatchOutcome {
        DispatchOutcome::ChannelFault {
            idx,
            ids: ChannelIds {
                local: self.local,
                remote,
            },
            opening: self.state == ChannelState::Opening,
            fault,
        }
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
    /// Acknowledging is what re-opens the sender's window, so doing it
    /// on arrival means the device may keep writing to a channel the
    /// application never reads — the buffer then grows without bound.
    ///
    /// With delayed-ack the answer is always "later": credit is returned
    /// as the application consumes bytes, and the budget we advertised
    /// bounds what can pile up meanwhile. Without it the window is a
    /// single packet, so waiting for the read on every packet would turn
    /// the channel into a ping-pong; the acknowledgement goes out at
    /// once while little is buffered, and is held back once the
    /// watermark's worth of bytes is waiting to be read.
    pub fn apply_write(&mut self, payload: &[u8]) -> Result<AckDecision, RxOverflow> {
        self.push_rx(payload)?;
        self.unacked = self.unacked.saturating_add(payload.len());
        if self.policy.ack == AckMode::Classic && self.rx_buf.len() < self.policy.watermark {
            if let Some(ack) = self.ack(payload.len()) {
                self.unacked = 0;
                return Ok(AckDecision::Now(ack));
            }
        }
        Ok(AckDecision::Hold)
    }

    /// Hand `taken` bytes of a freshly arrived packet to the caller,
    /// buffer whatever is left of it, and say what to acknowledge.
    pub fn deliver(
        &mut self,
        payload: &[u8],
        taken: usize,
    ) -> Result<Option<PendingAck>, RxOverflow> {
        if taken < payload.len() {
            self.push_rx(&payload[taken..])?;
            self.unacked = self.unacked.saturating_add(payload.len() - taken);
        }
        if self.policy.ack == AckMode::Delayed {
            return Ok(self.ack(taken).filter(|ack| ack.len > 0));
        }
        if self.rx_buf.len() >= self.policy.watermark {
            return Ok(None);
        }
        let Some(ack) = self.ack(self.unacked) else {
            return Ok(None);
        };
        self.unacked = 0;
        Ok(Some(ack))
    }

    /// Record that the application took `n` bytes, and say what to
    /// acknowledge as a result.
    pub fn consume(&mut self, n: usize) -> Option<PendingAck> {
        let len = self.ack_len(n, self.rx_buf.len())?;
        let ack = self.ack(len)?;
        self.unacked -= len;
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

    /// Copy buffered bytes into `buf`, and say what to acknowledge for
    /// taking them. `None` while an open channel has nothing buffered;
    /// once a closed one is drained, [`Error::ChannelClosed`] or the
    /// fault that closed it.
    pub fn take_buffered<E>(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, Option<PendingAck>)>, Error<E>> {
        if self.rx_buf.is_empty() {
            return if self.is_closed() {
                Err(self.closed_error())
            } else {
                Ok(None)
            };
        }
        let n = buf.len().min(self.rx_buf.len());
        buf[..n].copy_from_slice(&self.rx_buf[..n]);
        self.rx_buf.advance(n);
        Ok(Some((n, self.consume(n))))
    }

    fn push_rx(&mut self, payload: &[u8]) -> Result<(), RxOverflow> {
        if self.rx_buf.len().saturating_add(payload.len()) > self.policy.rx_cap {
            return Err(RxOverflow);
        }
        self.rx_buf.extend_from_slice(payload);
        Ok(())
    }

    pub fn apply_close(&mut self) {
        self.state = ChannelState::Closed;
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

    /// Take a place at the back of the send queue.
    #[allow(dead_code)] // used only by split::Writer
    pub fn send_enqueue(&mut self) -> u64 {
        let place = self.send_q_tail;
        self.send_q_tail += 1;
        place
    }

    /// The place currently allowed to reserve credit.
    #[allow(dead_code)] // used only by split::Writer
    pub fn send_turn(&self) -> u64 {
        self.send_q_head
    }

    /// Move the queue past the served head, skipping places whose
    /// writer already left.
    #[allow(dead_code)] // used only by split::Writer
    pub fn send_advance(&mut self) {
        self.send_q_head += 1;
        while self.send_q_gone.remove(&self.send_q_head) {
            self.send_q_head += 1;
        }
    }

    /// Leave the queue from `place` without being served. Returns
    /// whether the head moved — the caller then wakes the next writer.
    ///
    /// A leaving tail hands its place straight back — together with any
    /// holes that end up at the tail with it — so a caller that keeps
    /// queueing and dropping writes behind a blocked head reuses one
    /// place instead of growing the hole set.
    #[allow(dead_code)] // used only by split::Writer
    pub fn send_leave(&mut self, place: u64) -> bool {
        if place == self.send_q_head {
            self.send_advance();
            true
        } else if place + 1 == self.send_q_tail {
            self.send_q_tail = place;
            while self.send_q_tail > self.send_q_head
                && self.send_q_gone.remove(&(self.send_q_tail - 1))
            {
                self.send_q_tail -= 1;
            }
            false
        } else if place > self.send_q_head {
            self.send_q_gone.insert(place);
            false
        } else {
            false
        }
    }
}

/// What only the split halves ask of a slot: credit spent ahead of the
/// send it pays for, a channel closed for a fault, and how an open that
/// someone else dispatched went.
#[cfg_attr(not(feature = "split"), allow(dead_code))]
impl ChannelSlot {
    /// Where the channel stands.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// Whether a fault closed the channel, its CLSE sent with it.
    pub fn is_failed(&self) -> bool {
        self.failed.is_some()
    }

    /// Whether taking up to `want` buffered bytes now would owe the
    /// device an OKAY — what [`take_buffered`](Self::take_buffered)
    /// would answer, without taking anything.
    pub fn take_acks(&self, want: usize) -> bool {
        if self.rx_buf.is_empty() {
            return false;
        }
        let n = want.min(self.rx_buf.len());
        let remaining = self.rx_buf.len() - n;
        self.ack_len(n, remaining).is_some()
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
}

pub(crate) fn channel_ids_of<E>(
    channels: &[Option<ChannelSlot>],
    ch: ChannelId,
) -> Result<ChannelIds, Error<E>> {
    slot_for(channels, ch)
        .and_then(ChannelSlot::ids)
        .ok_or(Error::ChannelClosed)
}

/// The slot `ch` names, unless it has been freed or reused since.
pub(crate) fn slot_for(channels: &[Option<ChannelSlot>], ch: ChannelId) -> Option<&ChannelSlot> {
    channels
        .get(ch.slot)
        .and_then(|s| s.as_ref())
        .filter(|s| s.local == ch.local)
}

/// [`slot_for`], to change.
pub(crate) fn slot_for_mut(
    channels: &mut [Option<ChannelSlot>],
    ch: ChannelId,
) -> Option<&mut ChannelSlot> {
    channels
        .get_mut(ch.slot)
        .and_then(|s| s.as_mut())
        .filter(|s| s.local == ch.local)
}

#[cfg(all(test, feature = "split"))]
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

/// An open ADB channel tied to a [`Session`].
///
/// Provides [`read`](Self::read), [`write`](Self::write), and
/// [`close`](Self::close) methods.  Created by [`Session::open`] or
/// [`Connection::open`](crate::Connection::open).
///
/// Because `Channel` holds a mutable borrow on the session, only one
/// `Channel` can be active at a time on it.  For concurrent access to
/// multiple channels, use the [`ChannelId`]-based methods on
/// [`Connection`](crate::Connection) directly
/// ([`open_channel`](crate::Connection::open_channel),
/// [`read_channel`](crate::Connection::read_channel), etc.), or split the
/// connection and give each task a clone of the
/// [`Writer`](crate::Writer).
pub struct Channel<'a, S> {
    pub(crate) session: &'a mut S,
    pub(crate) id: ChannelId,
}

impl<S: Session> Channel<'_, S> {
    /// Read data from the channel into `buf`.
    ///
    /// Returns the number of bytes read. If data was already buffered
    /// (from a previous WRTE) the call returns immediately. Otherwise it
    /// waits until a WRTE arrives for this channel.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<S::IoError>> {
        self.session.read_channel(self.id, buf).await
    }

    /// Write data to the channel.
    ///
    /// Data is split into `max_payload`-sized chunks with appropriate
    /// flow-control (OKAY acknowledgement in legacy mode, credit-based
    /// budgeting in delayed ACK mode).
    pub async fn write(&mut self, data: &[u8]) -> Result<(), Error<S::IoError>> {
        self.session.write_channel(self.id, data).await
    }

    /// Read from the channel, but return early if `interrupt` resolves first.
    ///
    /// This is the primary way to combine channel reads with other async
    /// event sources (e.g. stdin, signals) without raw packet manipulation.
    /// If `interrupt` wins, the channel state is unchanged and the next
    /// call resumes normally.
    ///
    /// How quickly `interrupt` can win depends on the session. On a
    /// split [`Writer`](crate::Writer) it is raced against the wait for
    /// data. On a [`Connection`](crate::Connection) over TCP it is raced against the read
    /// itself, so a pending read is dropped the moment the interrupt is
    /// due. A transport that would lose data that way — USB, where
    /// cancelling a bulk transfer discards what the device already
    /// wrote into it — has the interrupt checked between reads instead,
    /// so it takes effect once the read in flight has finished. See
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
    ) -> Result<SelectResult<F::Output>, Error<S::IoError>> {
        self.session.select_channel(self.id, buf, interrupt).await
    }

    /// Close the channel, sending CLSE to the device and freeing the slot.
    ///
    /// Consumes the `Channel`.
    pub async fn close(self) -> Result<(), Error<S::IoError>> {
        self.session.close_channel(self.id).await
    }
}

#[cfg(test)]
mod tests {
    use super::ChannelSlot;
    use crate::base::ids::LocalId;
    use crate::base::negotiated::{AckMode, RxPolicy};

    #[test]
    fn cancellation_churn_behind_a_blocked_head_does_not_accumulate() {
        let policy = RxPolicy {
            ack: AckMode::Delayed,
            rx_cap: usize::MAX,
            watermark: 0,
        };
        let mut slot = ChannelSlot::opening(LocalId::from(1), policy);
        let _head = slot.send_enqueue();

        for _ in 0..1_000 {
            let mid = slot.send_enqueue();
            let tail = slot.send_enqueue();
            // Dropped mid-queue: a hole, while `tail` still lives...
            assert!(!slot.send_leave(mid));
            // ...and the leaving tail reclaims itself and the hole.
            assert!(!slot.send_leave(tail));
        }

        assert!(slot.send_q_gone.is_empty());
        assert_eq!(slot.send_q_tail, 1);
        assert_eq!(slot.send_q_head, 0);
    }
}
