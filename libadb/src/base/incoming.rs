//! Channels the device opened toward the host, waiting for a verdict.
//!
//! Kept apart from the channel table on purpose: on a split connection
//! the queue has a lock of its own, which some paths take without the
//! table's.

use alloc::collections::VecDeque;
use bytes::Bytes;

use super::ids::RemoteId;

/// A device-initiated OPEN waiting for the application's verdict.
#[derive(Debug)]
pub(crate) struct PendingOpen {
    /// The device's end of the channel it asks for.
    pub(crate) remote: RemoteId,
    /// OPEN's `arg1`: the device's receive credit, our send budget once
    /// accepted under delayed ACK.
    pub(crate) credit: u32,
    /// The service the device asked for, e.g. `tcp:8080\0`.
    pub(crate) destination: Bytes,
}

/// OPENs the device sent that nobody has decided on yet, oldest first.
#[derive(Debug, Default)]
pub(crate) struct IncomingQueue(VecDeque<PendingOpen>);

impl IncomingQueue {
    /// Requests waiting.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Queue a new arrival behind the rest.
    pub(crate) fn push_back(&mut self, pending: PendingOpen) {
        self.0.push_back(pending);
    }

    /// Put back a request taken out and left undecided: it was the
    /// oldest, and is again.
    pub(crate) fn push_front(&mut self, pending: PendingOpen) {
        self.0.push_front(pending);
    }

    /// Take the oldest request.
    pub(crate) fn pop_front(&mut self) -> Option<PendingOpen> {
        self.0.pop_front()
    }

    /// Drop the request the device sent from `remote`: it took it back.
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
