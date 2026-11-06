//! [`Session`]: what the protocol helpers open their channels on, and
//! [`ServiceChannel`], the open-read-close part of it a one-shot
//! service exchange needs.

use core::future::Future;

use super::channel::{Channel, ChannelId, SelectResult};
use super::protocol::features::Feature;
use crate::error::Error;

/// A connection the protocol helpers open their channels on.
///
/// Implemented for [`Connection`], which receives packets itself while
/// one of its channels is read, and for the split [`Writer`], whose
/// packets [`Reader::run`] receives. Every helper — [`shell`],
/// [`logcat`], [`sync`], [`exec`] and the rest — takes either, so on a
/// split connection several of them run at once, each from its own
/// task over its own clone of the `Writer`.
///
/// [`Connection`]: crate::Connection
/// [`Writer`]: crate::Writer
/// [`Reader::run`]: crate::Reader::run
/// [`shell`]: crate::shell
/// [`logcat`]: crate::logcat
/// [`sync`]: crate::sync
/// [`exec`]: crate::exec
pub trait Session {
    /// Transport error carried by this session's [`Error`].
    type IoError;

    /// Whether the device listed `feature` in its banner.
    fn advertises(&self, feature: &Feature) -> bool;

    /// Fail with [`Error::MissingFeature`] unless the device banner
    /// lists `feature`, as
    /// [`Connection::require_feature`](crate::Connection::require_feature)
    /// does.
    fn require_feature(&self, feature: Feature) -> Result<(), Error<Self::IoError>> {
        if self.advertises(&feature) {
            Ok(())
        } else {
            Err(Error::MissingFeature(feature))
        }
    }

    /// Open a channel to `destination` (a NUL-terminated service
    /// string such as `b"shell:ls\0"`).
    fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> impl Future<Output = Result<ChannelId, Error<Self::IoError>>>;

    /// Read from `ch` into `buf`, returning the number of bytes read.
    fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, Error<Self::IoError>>>;

    /// Write all of `data` to `ch`.
    fn write_channel(
        &mut self,
        ch: ChannelId,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Error<Self::IoError>>>;

    /// Read from `ch`, returning early if `interrupt` resolves first.
    /// The channel loses nothing to an interrupt: the next read picks
    /// up where this one left off.
    fn select_channel<F: Future>(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
        interrupt: F,
    ) -> impl Future<Output = Result<SelectResult<F::Output>, Error<Self::IoError>>>;

    /// Free `ch`'s slot and send CLSE for it. The slot is freed even if
    /// the CLSE fails.
    fn close_channel(
        &mut self,
        ch: ChannelId,
    ) -> impl Future<Output = Result<(), Error<Self::IoError>>>;

    /// Open a channel to `destination` as a [`Channel`] that borrows
    /// this session.
    fn open(
        &mut self,
        destination: &[u8],
    ) -> impl Future<Output = Result<Channel<'_, Self>, Error<Self::IoError>>>
    where
        Self: Sized,
    {
        async move {
            let id = self.open_channel(destination).await?;
            Ok(Channel { session: self, id })
        }
    }
}

impl<T> Session for super::connection::Connection<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write + crate::transport::ReadCancelSafety,
{
    type IoError = <T as embedded_io::ErrorType>::Error;

    fn advertises(&self, feature: &Feature) -> bool {
        self.negotiated().advertises(feature)
    }

    async fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<Self::IoError>> {
        Self::open_channel(self, destination).await
    }

    async fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<Self::IoError>> {
        Self::read_channel(self, ch, buf).await
    }

    async fn write_channel(
        &mut self,
        ch: ChannelId,
        data: &[u8],
    ) -> Result<(), Error<Self::IoError>> {
        Self::write_channel(self, ch, data).await
    }

    async fn select_channel<F: Future>(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<Self::IoError>> {
        Self::select_channel(self, ch, buf, interrupt).await
    }

    async fn close_channel(&mut self, ch: ChannelId) -> Result<(), Error<Self::IoError>> {
        Self::close_channel(self, ch).await
    }
}

#[cfg(feature = "split")]
impl<WH> Session for crate::split::Writer<WH>
where
    WH: embedded_io_async::Write,
{
    type IoError = <WH as embedded_io::ErrorType>::Error;

    fn advertises(&self, feature: &Feature) -> bool {
        self.negotiated().advertises(feature)
    }

    async fn open_channel(
        &mut self,
        destination: &[u8],
    ) -> Result<ChannelId, Error<Self::IoError>> {
        Self::open_channel(self, destination).await
    }

    async fn read_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<Self::IoError>> {
        Self::read_channel(self, ch, buf).await
    }

    async fn write_channel(
        &mut self,
        ch: ChannelId,
        data: &[u8],
    ) -> Result<(), Error<Self::IoError>> {
        Self::write_channel(self, ch, data).await
    }

    async fn select_channel<F: Future>(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
        interrupt: F,
    ) -> Result<SelectResult<F::Output>, Error<Self::IoError>> {
        Self::select_channel(self, ch, buf, interrupt).await
    }

    async fn close_channel(&mut self, ch: ChannelId) -> Result<(), Error<Self::IoError>> {
        Self::close_channel(self, ch).await
    }
}

/// A connection a one-shot service exchange can run on: open a service
/// channel, read it to close, close it back to free the slot.
///
/// Implemented for every [`Session`], and for the split [`Reader`],
/// which is not one: it opens, reads and closes channels but has no
/// `write_channel`. So [`reverse`] reaches the FFI's split halves too.
///
/// [`Reader`]: crate::Reader
/// [`reverse`]: crate::reverse
pub trait ServiceChannel {
    /// Transport error carried by this connection's [`Error`].
    type IoError;

    /// Open a channel to `dest` (a NUL-terminated service string).
    fn open_service_channel(
        &mut self,
        dest: &[u8],
    ) -> impl Future<Output = Result<ChannelId, Error<Self::IoError>>>;

    /// Read from a channel opened by [`open_service_channel`].
    ///
    /// [`open_service_channel`]: Self::open_service_channel
    fn read_service_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, Error<Self::IoError>>>;

    /// Send CLSE for a channel opened by [`open_service_channel`] and
    /// free its slot.
    ///
    /// [`open_service_channel`]: Self::open_service_channel
    fn close_service_channel(
        &mut self,
        ch: ChannelId,
    ) -> impl Future<Output = Result<(), Error<Self::IoError>>>;
}

impl<S: Session> ServiceChannel for S {
    type IoError = S::IoError;

    async fn open_service_channel(
        &mut self,
        dest: &[u8],
    ) -> Result<ChannelId, Error<Self::IoError>> {
        self.open_channel(dest).await
    }

    async fn read_service_channel(
        &mut self,
        ch: ChannelId,
        buf: &mut [u8],
    ) -> Result<usize, Error<Self::IoError>> {
        self.read_channel(ch, buf).await
    }

    async fn close_service_channel(&mut self, ch: ChannelId) -> Result<(), Error<Self::IoError>> {
        self.close_channel(ch).await
    }
}
