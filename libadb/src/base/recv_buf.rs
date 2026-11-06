//! [`RecvBuf`]: a caller's byte slice used as a receive buffer, read
//! into from a channel until a reply of known size is in.

use super::channel::Channel;
use super::session::Session;
use crate::error::Error;

/// The receive buffer of a service that parses replies in place:
/// `buf[head..tail]` is what arrived and has not been consumed.
pub(crate) struct RecvBuf<'b> {
    /// The caller's buffer.
    buf: &'b mut [u8],
    /// Where the bytes not consumed yet start.
    head: usize,
    /// One past the last byte read in.
    tail: usize,
}

impl<'b> RecvBuf<'b> {
    /// An empty receive buffer over `buf`.
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self {
            buf,
            head: 0,
            tail: 0,
        }
    }

    /// How many bytes the buffer holds in all: the longest reply
    /// [`fill_at_least`](Self::fill_at_least) can wait for.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The first `n` bytes not consumed yet, left in place. Panics if
    /// fewer than `n` are buffered: fill first.
    pub fn peek(&self, n: usize) -> &[u8] {
        &self.buf[self.head..self.tail][..n]
    }

    /// Consume the first `n` bytes not consumed yet and return them.
    /// They stay valid until the next call that reads into the buffer.
    /// Panics if fewer than `n` are buffered.
    pub fn take(&mut self, n: usize) -> &[u8] {
        let start = self.head;
        self.head += self.peek(n).len();
        &self.buf[start..self.head]
    }

    /// Consume the first `n` bytes not consumed yet. Panics if fewer
    /// than `n` are buffered.
    pub fn advance(&mut self, n: usize) {
        self.take(n);
    }

    /// The free space past the buffered bytes, for a caller to build an
    /// outgoing message in without allocating. [`compact`](Self::compact)
    /// first to make it as large as it gets.
    pub fn window(&mut self) -> &mut [u8] {
        &mut self.buf[self.tail..]
    }

    /// Move the bytes not consumed yet to the front of `buf`, freeing
    /// what lay before them for the next read.
    pub fn compact(&mut self) {
        if self.head > 0 {
            self.buf.copy_within(self.head..self.tail, 0);
            self.tail -= self.head;
            self.head = 0;
        }
    }

    /// Read from `channel` until at least `n` bytes not consumed yet are
    /// buffered, compacting once the end of `buf` is reached.
    ///
    /// Fails with [`Error::ReceiveBufferFull`] when `buf` is shorter
    /// than `n`, and with whatever the read fails with.
    pub async fn fill_at_least<S: Session>(
        &mut self,
        channel: &mut Channel<'_, S>,
        n: usize,
    ) -> Result<(), Error<S::IoError>> {
        if n > self.buf.len() {
            return Err(Error::ReceiveBufferFull);
        }
        while self.tail - self.head < n {
            if self.tail >= self.buf.len() {
                self.compact();
                if self.tail >= self.buf.len() {
                    return Err(Error::ReceiveBufferFull);
                }
            }
            let read = channel.read(&mut self.buf[self.tail..]).await?;
            self.tail += read;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let mut storage = [0u8; 16];
        let rb = RecvBuf::new(&mut storage);
        assert_eq!(rb.head, 0);
        assert_eq!(rb.tail, 0);
        assert_eq!(rb.buf.len(), 16);
    }

    #[test]
    fn compact_with_head_at_zero_is_a_noop() {
        let mut storage = [1u8, 2, 3, 4, 5, 0, 0, 0];
        let mut rb = RecvBuf::new(&mut storage);
        rb.tail = 5;

        rb.compact();

        assert_eq!(rb.head, 0);
        assert_eq!(rb.tail, 5);
        assert_eq!(&rb.buf[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn compact_shifts_unread_bytes_to_front() {
        let mut storage = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut rb = RecvBuf::new(&mut storage);
        rb.head = 3;
        rb.tail = 7;

        rb.compact();

        assert_eq!(rb.head, 0);
        assert_eq!(rb.tail, 4);
        assert_eq!(&rb.buf[..4], &[4, 5, 6, 7]);
    }

    #[test]
    fn compact_resets_when_all_bytes_consumed() {
        let mut storage = [1u8, 2, 3, 4];
        let mut rb = RecvBuf::new(&mut storage);
        rb.head = 4;
        rb.tail = 4;

        rb.compact();

        assert_eq!(rb.head, 0);
        assert_eq!(rb.tail, 0);
    }

    #[test]
    fn compact_reclaims_full_buffer_when_tail_at_end() {
        let mut storage = [10u8, 20, 30, 40];
        let mut rb = RecvBuf::new(&mut storage);
        rb.head = 2;
        rb.tail = 4;

        rb.compact();

        assert_eq!(rb.head, 0);
        assert_eq!(rb.tail, 2);
        assert_eq!(&rb.buf[..2], &[30, 40]);
    }

    #[test]
    fn take_consumes_what_peek_shows() {
        let mut storage = [1u8, 2, 3, 4, 5, 6];
        let mut rb = RecvBuf::new(&mut storage);
        rb.tail = 5;

        assert_eq!(rb.peek(2), &[1, 2]);
        assert_eq!(rb.take(3), &[1, 2, 3]);
        rb.advance(1);

        assert_eq!(rb.head, 4);
        assert_eq!(rb.peek(1), &[5]);
    }

    #[test]
    #[should_panic]
    fn peek_past_the_buffered_bytes_panics() {
        let mut storage = [0u8; 8];
        let mut rb = RecvBuf::new(&mut storage);
        rb.tail = 2;

        rb.peek(3);
    }

    #[test]
    #[should_panic]
    fn advance_past_the_buffered_bytes_panics() {
        let mut storage = [0u8; 8];
        let mut rb = RecvBuf::new(&mut storage);
        rb.tail = 2;

        rb.advance(3);
    }

    #[test]
    fn the_window_is_the_space_past_the_buffered_bytes() {
        let mut storage = [0u8; 8];
        let mut rb = RecvBuf::new(&mut storage);
        rb.head = 1;
        rb.tail = 3;

        assert_eq!(rb.window().len(), 5);
        rb.window()[0] = 9;
        assert_eq!(rb.buf[3], 9);
        assert_eq!(rb.capacity(), 8);
    }

    #[test]
    fn compact_of_single_byte_window_preserves_byte() {
        let mut storage = [1u8, 2, 3, 4];
        let mut rb = RecvBuf::new(&mut storage);
        rb.head = 2;
        rb.tail = 3;

        rb.compact();

        assert_eq!(rb.head, 0);
        assert_eq!(rb.tail, 1);
        assert_eq!(rb.buf[0], 3);
    }
}
