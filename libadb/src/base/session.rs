//! [`Session`]: what the protocol helpers open their channels on.

use core::future::Future;

use super::channel::{Channel, ChannelId, SelectResult};
use super::error::Error;
use super::protocol::features::Feature;

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

    /// Whether the device listed `feature` in its banner, or `None`
    /// when no banner was parsed.
    fn advertises(&self, feature: &Feature) -> Option<bool>;

    /// Fail with [`Error::MissingFeature`] if the device banner was
    /// parsed and does not list `feature`. A session without a banner
    /// passes, as with
    /// [`Connection::require_feature`](crate::Connection::require_feature).
    fn require_feature(&self, feature: Feature) -> Result<(), Error<Self::IoError>> {
        match self.advertises(&feature) {
            Some(false) => Err(Error::MissingFeature(feature)),
            _ => Ok(()),
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

    /// Send CLSE for `ch` and free its slot.
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

impl<T, const MC: usize, const MP: usize, const MF: usize> Session
    for super::connection::Connection<T, MC, MP, MF>
where
    T: embedded_io_async::Read + embedded_io_async::Write + crate::transport::ReadCancelSafety,
{
    type IoError = <T as embedded_io::ErrorType>::Error;

    fn advertises(&self, feature: &Feature) -> Option<bool> {
        self.device_banner_parsed().map(|b| b.has_feature(feature))
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
impl<WH, const MC: usize, const MP: usize, const MF: usize> Session
    for crate::split::Writer<WH, MC, MP, MF>
where
    WH: embedded_io_async::Write,
{
    type IoError = <WH as embedded_io::ErrorType>::Error;

    fn advertises(&self, feature: &Feature) -> Option<bool> {
        self.device_banner_parsed().map(|b| b.has_feature(feature))
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
