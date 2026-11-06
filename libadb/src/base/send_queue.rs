#[cfg(test)]
mod tests;

use alloc::collections::BTreeSet;

#[derive(Default)]
pub(crate) struct SendQueue {
    head: u64,
    tail: u64,
    gone: BTreeSet<u64>,
    sending: usize,
}

#[cfg_attr(not(feature = "split"), allow(dead_code))]
impl SendQueue {
    pub(crate) fn enqueue(&mut self) -> u64 {
        let place = self.tail;
        self.tail += 1;
        place
    }

    pub(crate) fn turn(&self) -> u64 {
        self.head
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub(crate) fn is_sending(&self) -> bool {
        self.sending > 0
    }

    pub(crate) fn serve(&mut self) {
        self.sending += 1;
        self.advance();
    }

    pub(crate) fn finish(&mut self) {
        self.sending -= 1;
    }

    fn advance(&mut self) {
        self.head += 1;
        while self.gone.remove(&self.head) {
            self.head += 1;
        }
    }

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
