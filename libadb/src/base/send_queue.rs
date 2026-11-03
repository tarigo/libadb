//! The order concurrent writers on one channel take its credit in.

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

    /// Move the queue past the served head, skipping places whose
    /// writer already left.
    pub(crate) fn advance(&mut self) {
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

#[cfg(test)]
mod tests {
    use super::SendQueue;

    #[test]
    fn cancellation_churn_behind_a_blocked_head_does_not_accumulate() {
        let mut queue = SendQueue::default();
        let _head = queue.enqueue();

        for _ in 0..1_000 {
            let mid = queue.enqueue();
            let tail = queue.enqueue();
            // Dropped mid-queue: a hole, while `tail` still lives...
            assert!(!queue.leave(mid));
            // ...and the leaving tail reclaims itself and the hole.
            assert!(!queue.leave(tail));
        }

        assert!(queue.gone.is_empty());
        assert_eq!(queue.tail, 1);
        assert_eq!(queue.head, 0);
    }
}
