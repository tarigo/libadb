use alloc::boxed::Box;
use bytes::Bytes;

use super::channel::ChannelId;
use super::ids::{ChannelIds, LocalId, RemoteId};
use super::negotiated::RxPolicy;
use super::protocol::command::Command;
use super::protocol::Packet;
use super::slot::{AckDecision, ChannelFault, ChannelSlot, ChannelState, PendingAck};
use crate::error::{Error, NoFreeChannels};

#[cfg_attr(not(feature = "split"), allow(dead_code))]
pub(crate) enum DispatchOutcome {
    AckWrite {
        idx: usize,
        ack: PendingAck,
    },
    CreditGranted {
        idx: usize,
    },
    SlotClosed {
        idx: usize,
    },
    DataBuffered {
        idx: usize,
    },
    IncomingOpen {
        remote: RemoteId,
        credit: u32,
        destination: Bytes,
    },
    CancelPendingOpen {
        remote: RemoteId,
    },
    StrayReady {
        ids: ChannelIds,
    },
    ChannelFault {
        idx: usize,
        ids: ChannelIds,
        opening: bool,
        fault: ChannelFault,
    },
    Unmatched,
}

pub(crate) struct ChannelTable {
    slots: Box<[Option<ChannelSlot>]>,
    next_local_id: u32,
    policy: RxPolicy,
}

impl ChannelTable {
    pub(crate) fn new(len: usize, policy: RxPolicy) -> Self {
        Self {
            slots: (0..len).map(|_| None).collect(),
            next_local_id: 1,
            policy,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn allocate(&mut self) -> Result<ChannelId, NoFreeChannels> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(NoFreeChannels)?;
        let local = LocalId::from(self.next_local_id);
        self.next_local_id = self.next_local_id.wrapping_add(1).max(1);
        Ok(ChannelId { slot, local })
    }

    pub(crate) fn insert_opening(&mut self, ch: ChannelId) -> &mut ChannelSlot {
        let slot = ChannelSlot::opening(ch.local, self.policy);
        self.fill(ch, slot)
    }

    pub(crate) fn insert_accepted(&mut self, ch: ChannelId, remote: RemoteId, credit: u32) {
        let ids = ChannelIds {
            local: ch.local,
            remote,
        };
        self.fill(ch, ChannelSlot::accepted(ids, credit, self.policy));
    }

    fn fill(&mut self, ch: ChannelId, slot: ChannelSlot) -> &mut ChannelSlot {
        let entry = &mut self.slots[ch.slot];
        debug_assert!(
            entry.is_none(),
            "slot {} filled while a channel still holds it",
            ch.slot
        );
        entry.insert(slot)
    }

    pub(crate) fn get(&self, ch: ChannelId) -> Option<&ChannelSlot> {
        self.slots
            .get(ch.slot)
            .and_then(Option::as_ref)
            .filter(|s| s.local() == ch.local)
    }

    pub(crate) fn get_mut(&mut self, ch: ChannelId) -> Option<&mut ChannelSlot> {
        self.slots
            .get_mut(ch.slot)
            .and_then(Option::as_mut)
            .filter(|s| s.local() == ch.local)
    }

    pub(crate) fn ids<E>(&self, ch: ChannelId) -> Result<ChannelIds, Error<E>> {
        self.get(ch)
            .and_then(ChannelSlot::ids)
            .ok_or(Error::ChannelClosed)
    }

    pub(crate) fn free(&mut self, ch: ChannelId) -> Option<ChannelSlot> {
        self.get(ch)?;
        self.slots[ch.slot].take()
    }

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

    pub(crate) fn dispatch(&mut self, pkt: &Packet) -> DispatchOutcome {
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
            if let Some(idx) = self.close_remote(remote) {
                return DispatchOutcome::SlotClosed { idx };
            }
            return DispatchOutcome::CancelPendingOpen { remote };
        }
        for (idx, slot_opt) in self.slots.iter_mut().enumerate() {
            let Some(slot) = slot_opt else { continue };
            let ours = pkt.arg1 == slot.local().raw();
            match pkt.command {
                Command::Write | Command::Ready if ours && slot.is_failed() => {
                    return DispatchOutcome::Unmatched;
                }
                Command::Write if ours => {
                    return match slot.apply_write(&pkt.data) {
                        Ok(AckDecision::Now(ack)) => DispatchOutcome::AckWrite { idx, ack },
                        Ok(AckDecision::Hold) => DispatchOutcome::DataBuffered { idx },
                        Err(broken) => fault(idx, slot, remote, broken),
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
