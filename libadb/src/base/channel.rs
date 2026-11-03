use core::future::Future;

use super::ids::LocalId;
use super::session::Session;
use crate::error::Error;

/// Result of [`Channel::select`] / [`Session::select_channel`].
#[derive(Debug)]
pub enum SelectResult<T> {
    /// The channel produced data — value is the number of bytes read.
    Data(usize),
    /// The interrupt future completed with this value before channel data
    /// arrived. The channel state is unchanged and the next read will
    /// pick up where this one left off.
    Interrupted(T),
}

/// Opaque handle to an open ADB channel.
///
/// Used with [`Session::open_channel`], [`read_channel`](Session::read_channel),
/// [`write_channel`](Session::write_channel), [`close_channel`](Session::close_channel),
/// and the same methods on [`Connection`](crate::Connection) and the split
/// [`Writer`](crate::Writer).
/// A stale handle from a closed channel never aliases a later reopened
/// one — it returns [`Error::ChannelClosed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId {
    pub(crate) slot: usize,
    pub(crate) local: LocalId,
}

impl ChannelId {
    /// Build a `ChannelId` from raw `(slot, local_id)`. Intended for
    /// FFI bridges that round-trip a handle through an opaque integer;
    /// ordinary Rust callers should use the `ChannelId` returned by
    /// [`Session::open_channel`] directly.
    pub fn from_raw(slot: usize, local_id: u32) -> Self {
        Self {
            slot,
            local: LocalId::from(local_id),
        }
    }

    /// Slot index in the connection's channel table.
    pub fn slot(self) -> usize {
        self.slot
    }

    /// ADB wire `local_id` for this channel — unique per OPEN.
    pub fn local_id(self) -> u32 {
        self.local.raw()
    }
}

/// An open ADB channel tied to a [`Session`].
///
/// Provides [`read`](Self::read), [`write`](Self::write), and
/// [`close`](Self::close) methods.  Created by [`Session::open`] or
/// [`Connection::open`](crate::Connection::open).
///
/// Because `Channel` holds a mutable borrow on the session, only one
/// `Channel` can be active at a time on it.  For concurrent access to
/// multiple channels, use the [`ChannelId`]-based methods on
/// [`Connection`](crate::Connection) directly
/// ([`open_channel`](crate::Connection::open_channel),
/// [`read_channel`](crate::Connection::read_channel), etc.), or split the
/// connection and give each task a clone of the
/// [`Writer`](crate::Writer).
pub struct Channel<'a, S> {
    pub(crate) session: &'a mut S,
    pub(crate) id: ChannelId,
}

impl<S: Session> Channel<'_, S> {
    /// Read data from the channel into `buf`.
    ///
    /// Returns the number of bytes read. If data was already buffered
    /// (from a previous WRTE) the call returns immediately. Otherwise it
    /// waits until a WRTE arrives for this channel.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<S::IoError>> {
        self.session.read_channel(self.id, buf).await
    }

    /// Write data to the channel.
    ///
    /// Data is split into `max_payload`-sized chunks with appropriate
    /// flow-control (OKAY acknowledgement in legacy mode, credit-based
    /// budgeting in delayed ACK mode).
    pub async fn write(&mut self, data: &[u8]) -> Result<(), Error<S::IoError>> {
        self.session.write_channel(self.id, data).await
    }

    /// Read from the channel, but return early if `interrupt` resolves first.
    ///
    /// This is the primary way to combine channel reads with other async
    /// event sources (e.g. stdin, signals) without raw packet manipulation.
    /// If `interrupt` wins, the channel state is unchanged and the next
    /// call resumes normally.
    ///
    /// How quickly `interrupt` can win depends on the session. On a
    /// split [`Writer`](crate::Writer) it is raced against the wait for
    /// data. On a [`Connection`](crate::Connection) over TCP it is raced against the read
    /// itself, so a pending read is dropped the moment the interrupt is
    /// due. A transport that would lose data that way — USB, where
    /// cancelling a bulk transfer discards what the device already
    /// wrote into it — has the interrupt checked between reads instead,
    /// so it takes effect once the read in flight has finished. See
    /// [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
    ///
    /// ```ignore
    /// loop {
    ///     match ch.select(&mut buf, stdin_rx.recv()).await? {
    ///         SelectResult::Data(n) => { /* handle buf[..n] */ }
    ///         SelectResult::Interrupted(input) => {
    ///             ch.write(&input).await?;
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn select<F: Future>(
        &mut self,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<S::IoError>> {
        self.session.select_channel(self.id, buf, interrupt).await
    }

    /// Close the channel, sending CLSE to the device and freeing the slot.
    ///
    /// Consumes the `Channel`.
    pub async fn close(self) -> Result<(), Error<S::IoError>> {
        self.session.close_channel(self.id).await
    }
}
