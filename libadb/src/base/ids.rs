use super::protocol::command::Command;
use super::protocol::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LocalId(u32);

impl LocalId {
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for LocalId {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RemoteId(u32);

impl RemoteId {
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for RemoteId {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelIds {
    pub(crate) local: LocalId,
    pub(crate) remote: RemoteId,
}

impl ChannelIds {
    pub(crate) fn closed_by(&self, pkt: &Packet) -> bool {
        pkt.command == Command::Close
            && (pkt.arg1 == self.local.raw() || (pkt.arg1 == 0 && pkt.arg0 == self.remote.raw()))
    }
}
