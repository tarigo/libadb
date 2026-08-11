use alloc::vec::Vec;

use crate::base::error::ProtocolError;

use super::{parse_header, Frame, EXIT, HEADER_SIZE, STDERR, STDOUT};

pub(super) fn make_frame(id: u8, payload: Vec<u8>) -> Result<Frame, ProtocolError> {
    Ok(match id {
        STDOUT => Frame::Stdout(payload),
        STDERR => Frame::Stderr(payload),
        EXIT => Frame::Exit(
            payload
                .first()
                .copied()
                .ok_or(ProtocolError::ShortExitPayload)?,
        ),
        other => Frame::Other { id: other, payload },
    })
}

/// Stateful shell_v2 frame decoder — the pure (IO-free) half of
/// [`Shell`](super::Shell). Owns the ringbuffer cursors and the "large
/// frame" split state; operates on a caller-supplied byte slice so it
/// can be exercised by unit tests and fuzzers without building a
/// [`Shell`](super::Shell).
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameDecoder {
    pub(crate) head: usize,
    pub(crate) tail: usize,
    pub(crate) large_id: u8,
    pub(crate) large_remaining: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes already decoded from `rx` — safe to overwrite.
    pub fn head(&self) -> usize {
        self.head
    }

    /// One past the last valid byte in `rx`.
    pub fn tail(&self) -> usize {
        self.tail
    }

    /// Number of bytes still to be delivered from the current oversized
    /// frame (0 when no frame is mid-flight).
    pub fn large_remaining(&self) -> usize {
        self.large_remaining
    }

    /// Advance `tail` after `n` bytes have been appended to `rx[tail..]`.
    pub fn commit(&mut self, n: usize) {
        self.tail += n;
    }

    /// Compact `rx` so unread bytes sit at offset 0. Mirrors the
    /// ring-buffer compaction performed internally by `Shell`.
    pub fn compact(&mut self, rx: &mut [u8]) {
        if self.head > 0 {
            rx.copy_within(self.head..self.tail, 0);
            self.tail -= self.head;
            self.head = 0;
        }
    }

    /// Try to decode one frame from the buffered bytes in `rx` and
    /// return `(id, payload)` where `payload` borrows from `rx`.
    ///
    /// Zero-alloc primitive — the returned slice stays valid until the
    /// next call that mutates the decoder or `rx` (typically
    /// [`commit`](Self::commit) or [`compact`](Self::compact)).
    ///
    /// When a frame (header + payload) does not fit in `rx` — i.e. when
    /// `HEADER_SIZE + payload_len > rx.len()` — it is delivered in
    /// multiple consecutive chunks that share the same `id`.
    pub fn try_next_raw_ref<'a>(
        &mut self,
        rx: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, ProtocolError> {
        if self.large_remaining > 0 {
            let buffered = self.tail - self.head;
            if buffered == 0 {
                return Ok(None);
            }
            let (id, payload) = self.consume_large_ref(rx, buffered);
            return Ok(Some((id, payload)));
        }

        let buffered = self.tail - self.head;
        if buffered < HEADER_SIZE {
            return Ok(None);
        }
        let hdr_start = self.head;
        let hdr: [u8; HEADER_SIZE] = rx[hdr_start..hdr_start + HEADER_SIZE].try_into().unwrap();
        let (id, length) = parse_header(&hdr);

        let length = length as usize;
        let total = HEADER_SIZE
            .checked_add(length)
            .ok_or(ProtocolError::PayloadTooLarge)?;

        if total > rx.len() {
            self.large_id = id;
            self.large_remaining = length;
            self.head = hdr_start + HEADER_SIZE;

            let available = self.tail - self.head;
            if available == 0 {
                self.reset_if_drained();
                return Ok(None);
            }
            let (_, payload) = self.consume_large_ref(rx, available);
            return Ok(Some((id, payload)));
        }

        if buffered < total {
            return Ok(None);
        }

        let payload_start = hdr_start + HEADER_SIZE;
        let payload_end = payload_start + length;
        self.head = payload_end;
        self.reset_if_drained();

        Ok(Some((id, &rx[payload_start..payload_end])))
    }

    /// Allocating wrapper over [`try_next_raw_ref`](Self::try_next_raw_ref).
    ///
    /// Prefer the `_ref` variant in throughput-sensitive paths;
    /// `try_next_raw` is kept for call sites that need an owned payload
    /// across subsequent decoder calls (e.g. because they decode into a
    /// `Frame`).
    pub fn try_next_raw(&mut self, rx: &[u8]) -> Result<Option<(u8, Vec<u8>)>, ProtocolError> {
        Ok(self
            .try_next_raw_ref(rx)?
            .map(|(id, payload)| (id, payload.to_vec())))
    }

    fn consume_large_ref<'a>(&mut self, rx: &'a [u8], available: usize) -> (u8, &'a [u8]) {
        let take = available.min(self.large_remaining);
        let id = self.large_id;
        let start = self.head;
        self.head += take;
        self.large_remaining -= take;
        self.reset_if_drained();
        (id, &rx[start..start + take])
    }

    fn reset_if_drained(&mut self) {
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
    }

    /// Try to decode one frame from the buffered bytes in `rx`.
    ///
    /// See [`Shell::try_next_frame`](super::Shell::try_next_frame) for
    /// the semantic contract; this method performs the same work without
    /// the IO-capable wrapper.
    pub fn try_next_frame(&mut self, rx: &[u8]) -> Result<Option<Frame>, ProtocolError> {
        self.try_next_raw(rx)?
            .map(|(id, p)| make_frame(id, p))
            .transpose()
    }
}
