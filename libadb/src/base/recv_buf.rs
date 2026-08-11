use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

use super::channel::Channel;
use super::error::Error;

pub(crate) struct RecvBuf<'b> {
    pub buf: &'b mut [u8],
    pub head: usize,
    pub tail: usize,
}

impl<'b> RecvBuf<'b> {
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self {
            buf,
            head: 0,
            tail: 0,
        }
    }

    pub fn compact(&mut self) {
        if self.head > 0 {
            self.buf.copy_within(self.head..self.tail, 0);
            self.tail -= self.head;
            self.head = 0;
        }
    }

    pub async fn fill_at_least<T, const MC: usize, const MP: usize, const MF: usize>(
        &mut self,
        channel: &mut Channel<'_, T, MC, MP, MF>,
        n: usize,
    ) -> Result<(), Error<<T as ErrorType>::Error>>
    where
        T: Read + Write,
    {
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
