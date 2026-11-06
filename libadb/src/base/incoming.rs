use alloc::collections::VecDeque;
use bytes::Bytes;

use super::ids::RemoteId;

#[derive(Debug)]
pub(crate) struct PendingOpen {
    pub(crate) remote: RemoteId,
    pub(crate) credit: u32,
    pub(crate) destination: Bytes,
}

#[derive(Debug, Default)]
pub(crate) struct IncomingQueue(VecDeque<PendingOpen>);

impl IncomingQueue {
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn push_back(&mut self, pending: PendingOpen) {
        self.0.push_back(pending);
    }

    pub(crate) fn push_front(&mut self, pending: PendingOpen) {
        self.0.push_front(pending);
    }

    pub(crate) fn pop_front(&mut self) -> Option<PendingOpen> {
        self.0.pop_front()
    }

    pub(crate) fn withdraw(&mut self, remote: RemoteId) {
        self.0.retain(|p| p.remote != remote);
    }
}

#[cfg(all(test, feature = "split"))]
impl IncomingQueue {
    /// The oldest request, left in place.
    pub(crate) fn front(&self) -> Option<&PendingOpen> {
        self.0.front()
    }
}
