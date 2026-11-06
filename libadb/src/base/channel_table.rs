//! The channel table: every channel's slot, the ids they are handed out
//! under, and where a packet from the device lands among them.

use alloc::boxed::Box;
use bytes::Bytes;

use super::channel::ChannelId;
use super::ids::{ChannelIds, LocalId, RemoteId};
use super::negotiated::RxPolicy;
use super::protocol::command::Command;
use super::protocol::Packet;
use super::slot::{AckDecision, ChannelFault, ChannelSlot, ChannelState, PendingAck};
use crate::error::{Error, NoFreeChannels, RxOverflow};

/// What a packet did to the channel table, and what is left for
/// whoever dispatched it to do. The slot indices and a fault's ids are
/// read only by `split::Reader`.
#[cfg_attr(not(feature = "split"), allow(dead_code))]
pub(crate) enum DispatchOutcome {
    /// A WRTE was buffered and has to be acknowledged now.
    AckWrite {
        idx: usize,
        ack: PendingAck,
    },
    /// An OKAY refilled the slot's send budget: one writer can proceed.
    CreditGranted {
        idx: usize,
    },
    /// A CLSE closed the slot: every waiter has to see the error.
    SlotClosed {
        idx: usize,
    },
    /// A WRTE was buffered with its acknowledgement held back until it
    /// is read.
    DataBuffered {
        idx: usize,
    },
    /// The device opened a channel toward the host (`adb reverse`), to be
    /// queued for a verdict: READY on accept, CLSE on refusal.
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
        idx: usize,
        ids: ChannelIds,
        /// The slot was waiting for the device's answer to its OPEN.
        opening: bool,
        fault: ChannelFault,
    },
    Unmatched,
}

/// Every channel of a connection, one slot each, allocated up front.
pub(crate) struct ChannelTable {
    slots: Box<[Option<ChannelSlot>]>,
    /// The id the next channel gets.
    next_local_id: u32,
    /// What every slot's receive side goes by.
    policy: RxPolicy,
}

impl ChannelTable {
    /// `len` empty slots whose channels will go by `policy`.
    pub(crate) fn new(len: usize, policy: RxPolicy) -> Self {
        Self {
            slots: (0..len).map(|_| None).collect(),
            next_local_id: 1,
            policy,
        }
    }

    /// How many slots there are, free or not.
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// A free slot and a fresh local id for a new channel. The slot
    /// stays free until [`insert_opening`](Self::insert_opening) or
    /// [`insert_accepted`](Self::insert_accepted) fills it.
    pub(crate) fn allocate(&mut self) -> Result<ChannelId, NoFreeChannels> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(NoFreeChannels)?;
        let local = LocalId::from(self.next_local_id);
        // adbd reads a zero id as none at all.
        self.next_local_id = self.next_local_id.wrapping_add(1).max(1);
        Ok(ChannelId { slot, local })
    }

    /// Fill `ch`'s slot with a channel of ours whose OPEN waits for the
    /// device's READY. `ch` comes from [`allocate`](Self::allocate),
    /// its slot still free.
    pub(crate) fn insert_opening(&mut self, ch: ChannelId) -> &mut ChannelSlot {
        let slot = ChannelSlot::opening(ch.local, self.policy);
        self.fill(ch, slot)
    }

    /// Fill `ch`'s slot with a channel the device opened from `remote`,
    /// its OPEN granting `credit`. `ch` comes from
    /// [`allocate`](Self::allocate), its slot still free.
    pub(crate) fn insert_accepted(&mut self, ch: ChannelId, remote: RemoteId, credit: u32) {
        let ids = ChannelIds {
            local: ch.local,
            remote,
        };
        self.fill(ch, ChannelSlot::accepted(ids, credit, self.policy));
    }

    /// Put `slot` where `ch` was allocated. Only the two inserts fill a
    /// slot, and [`dispatch`](Self::dispatch) touches none that is
    /// empty, so an occupant here would be a live channel overwritten.
    fn fill(&mut self, ch: ChannelId, slot: ChannelSlot) -> &mut ChannelSlot {
        let entry = &mut self.slots[ch.slot];
        debug_assert!(
            entry.is_none(),
            "slot {} filled while a channel still holds it",
            ch.slot
        );
        entry.insert(slot)
    }

    /// The slot `ch` names, unless it has been freed or reused since.
    pub(crate) fn get(&self, ch: ChannelId) -> Option<&ChannelSlot> {
        self.slots
            .get(ch.slot)
            .and_then(Option::as_ref)
            .filter(|s| s.local() == ch.local)
    }

    /// [`get`](Self::get), to change.
    pub(crate) fn get_mut(&mut self, ch: ChannelId) -> Option<&mut ChannelSlot> {
        self.slots
            .get_mut(ch.slot)
            .and_then(Option::as_mut)
            .filter(|s| s.local() == ch.local)
    }

    /// Both ends of `ch`. [`Error::ChannelClosed`] once the slot is
    /// gone, and while its OPEN still waits for an answer: before the
    /// device names its end there is nothing to address.
    pub(crate) fn ids<E>(&self, ch: ChannelId) -> Result<ChannelIds, Error<E>> {
        self.get(ch)
            .and_then(ChannelSlot::ids)
            .ok_or(Error::ChannelClosed)
    }

    /// Free `ch`'s slot, handing back what it held.
    pub(crate) fn free(&mut self, ch: ChannelId) -> Option<ChannelSlot> {
        self.get(ch)?;
        self.slots[ch.slot].take()
    }

    /// Close the channel whose device end is `remote`, and say which
    /// slot it was in. A zero id names no end, so it closes nothing.
    pub(crate) fn close_remote(&mut self, remote: RemoteId) -> Option<usize> {
        if remote.raw() == 0 {
            return None;
        }
        let idx = self.slots.iter().position(|s| {
            s.as_ref()
                .and_then(ChannelSlot::ids)
                .is_some_and(|ids| ids.remote == remote)
        })?;
        self.slots[idx].as_mut()?.apply_close();
        Some(idx)
    }

    /// Let `pkt` land where it belongs. A WRTE that would push a
    /// channel past its receive cap is a [`ChannelFault::RxOverflow`]
    /// instead of a bigger buffer.
    pub(crate) fn dispatch(&mut self, pkt: &Packet) -> DispatchOutcome {
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
        let remote = RemoteId::from(pkt.arg0);
        if pkt.command == Command::Close && pkt.arg1 == 0 {
            // The withdrawal may have crossed our READY in flight: the
            // request is then no longer queued but an accepted slot, and
            // has to close like any remote CLSE — the cancel handlers only
            // reach requests still awaiting a verdict.
            if let Some(idx) = self.close_remote(remote) {
                return DispatchOutcome::SlotClosed { idx };
            }
            return DispatchOutcome::CancelPendingOpen { remote };
        }
        for (idx, slot_opt) in self.slots.iter_mut().enumerate() {
            let Some(slot) = slot_opt else { continue };
            let ours = pkt.arg1 == slot.local().raw();
            match pkt.command {
                // A channel closed for a fault takes nothing more: data that
                // was still in flight would read as if no gap came before it.
                Command::Write | Command::Ready if ours && slot.is_failed() => {
                    return DispatchOutcome::Unmatched;
                }
                Command::Write if ours => {
                    return match slot.apply_write(&pkt.data) {
                        Ok(AckDecision::Now(ack)) => DispatchOutcome::AckWrite { idx, ack },
                        Ok(AckDecision::Hold) => DispatchOutcome::DataBuffered { idx },
                        Err(RxOverflow) => fault(idx, slot, remote, ChannelFault::RxOverflow),
                    };
                }
                Command::Ready if ours => {
                    let granted = if slot.state() == ChannelState::Opening {
                        slot.accept_open_ready(remote, &pkt.data)
                    } else {
                        slot.apply_ready(&pkt.data)
                    };
                    return match granted {
                        Ok(()) => DispatchOutcome::CreditGranted { idx },
                        Err(e) => fault(idx, slot, remote, ChannelFault::Protocol(e)),
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
}

#[cfg(test)]
impl ChannelTable {
    /// Slots that hold a channel.
    pub(crate) fn in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

/// `remote` comes from the packet: a slot still opening has none of its
/// own yet.
fn fault(idx: usize, slot: &ChannelSlot, remote: RemoteId, fault: ChannelFault) -> DispatchOutcome {
    DispatchOutcome::ChannelFault {
        idx,
        ids: ChannelIds {
            local: slot.local(),
            remote,
        },
        opening: slot.state() == ChannelState::Opening,
        fault,
    }
}
