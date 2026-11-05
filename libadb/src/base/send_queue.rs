//! The order concurrent writers on one channel take its credit in.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeSet;

/// Keeps concurrent `split::Writer`s on one channel in arrival order:
/// places are handed out by [`enqueue`](Self::enqueue), and only the
/// one at the head may reserve credit.
#[derive(Default)]
pub(crate) struct SendQueue {
    /// The place currently allowed to reserve credit.
    head: u64,
    /// The place the next writer gets.
    tail: u64,
    /// Places whose writer left the queue unserved; skipped when the
    /// head reaches them. Bounded: a hole is only recorded below a
    /// place still occupied — a leaving tail reclaims itself and any
    /// holes adjacent to it — so cancellation churn cannot grow this
    /// past the caller's own peak of concurrent writers.
    gone: BTreeSet<u64>,
    /// Writers served and still sending what they reserved.
    sending: usize,
}

#[cfg_attr(not(feature = "split"), allow(dead_code))]
impl SendQueue {
    /// Take a place at the back of the queue.
    pub(crate) fn enqueue(&mut self) -> u64 {
        let place = self.tail;
        self.tail += 1;
        place
    }

    /// The place currently allowed to reserve credit.
    pub(crate) fn turn(&self) -> u64 {
        self.head
    }

    /// Whether no writer holds a place: each was served, or left.
    pub(crate) fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Whether a writer [`serve`](Self::serve) let through has yet to
    /// [`finish`](Self::finish).
    pub(crate) fn is_sending(&self) -> bool {
        self.sending > 0
    }

    /// Serve the head: it leaves the queue with a send to finish.
    pub(crate) fn serve(&mut self) {
        self.sending += 1;
        self.advance();
    }

    /// One writer [`serve`](Self::serve) let through is done sending.
    pub(crate) fn finish(&mut self) {
        self.sending -= 1;
    }

    /// Move the queue past the head, skipping places whose writer
    /// already left.
    fn advance(&mut self) {
        self.head += 1;
        while self.gone.remove(&self.head) {
            self.head += 1;
        }
    }

    /// Leave the queue from `place` without being served. Returns
    /// whether the head moved — the caller then wakes the next writer.
    ///
    /// A leaving tail hands its place straight back — together with any
    /// holes that end up at the tail with it — so a caller that keeps
    /// queueing and dropping writes behind a blocked head reuses one
    /// place instead of growing the hole set.
    pub(crate) fn leave(&mut self, place: u64) -> bool {
        if place == self.head {
            self.advance();
            true
        } else if place + 1 == self.tail {
            self.tail = place;
            while self.tail > self.head && self.gone.remove(&(self.tail - 1)) {
                self.tail -= 1;
            }
            false
        } else if place > self.head {
            self.gone.insert(place);
            false
        } else {
            false
        }
    }
}
