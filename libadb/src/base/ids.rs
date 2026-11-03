//! The ids a channel goes by on the wire, one per end.

use super::protocol::command::Command;
use super::protocol::Packet;

/// The id this host gave its end of a channel: `arg0` of what we send
/// on it, `arg1` of what the device sends back. Handed out from 1 on,
/// since adbd reads a zero id as none at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LocalId(u32);

impl LocalId {
    /// The id as it goes on the wire.
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for LocalId {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

/// The id the device gave its end of a channel: `arg0` of what it sends
/// on it, `arg1` of what we send back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RemoteId(u32);

impl RemoteId {
    /// The id as it goes on the wire.
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for RemoteId {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

/// Both ends of a channel: what a WRTE, OKAY or CLSE on it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelIds {
    /// Our end.
    pub(crate) local: LocalId,
    /// The device's end.
    pub(crate) remote: RemoteId,
}

impl ChannelIds {
    /// Whether `pkt` is a CLSE that closes this channel. The ordinary
    /// form names our id in `arg1`; a zero-`arg1` withdrawal whose OPEN
    /// we already accepted — it crossed our READY in flight — names the
    /// device's id in `arg0`.
    pub(crate) fn closed_by(&self, pkt: &Packet) -> bool {
        pkt.command == Command::Close
            && (pkt.arg1 == self.local.raw() || (pkt.arg1 == 0 && pkt.arg0 == self.remote.raw()))
    }
}
