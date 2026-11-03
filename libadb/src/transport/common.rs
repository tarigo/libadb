//! [`Transport`], one connection type over either TCP or USB, and
//! [`NoUsb`] for the USB half of a build or call site that has none.

#[cfg(test)]
mod tests;

use embedded_io::{ErrorKind, ErrorType};
use embedded_io_async::{Read, Write};

#[cfg(feature = "tls")]
use crate::transport::tls::MaybeTls;
use crate::transport::Splittable;

/// A transport that is either TCP or USB.
///
/// Both halves are type parameters, so a build may carry several
/// runtimes and several USB backends at once and each call site says
/// which pair it wants. Use [`NoUsb`] for `U` at a call site that wants
/// no USB at all.
pub enum Transport<T, U> {
    Tcp(T),
    Usb(U),
}

/// Stand-in for the USB half of a [`Transport`] in builds without a USB
/// backend. Has no values, so [`Transport::Usb`] is unreachable.
pub enum NoUsb {}

impl ErrorType for NoUsb {
    type Error = NoUsbError;
}

impl Read for NoUsb {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        match *self {}
    }
}

impl Write for NoUsb {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        match *self {}
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match *self {}
    }
}

impl Splittable for NoUsb {
    type ReadHalf = NoUsb;
    type WriteHalf = NoUsb;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        match self {}
    }
}

impl<R> crate::transport::UsbBackend<R> for NoUsb {
    type Transport = NoUsb;
    type Error = NoBackend;

    fn connect_by_selector(_: crate::transport::uri::UsbSelector<'_>) -> Result<NoUsb, NoBackend> {
        Err(NoBackend)
    }
}

impl crate::transport::ReadCancelSafety for NoUsb {
    fn read_cancel_safe(&self) -> bool {
        match *self {}
    }
}

impl<T, U> crate::transport::ReadCancelSafety for Transport<T, U>
where
    T: crate::transport::ReadCancelSafety,
    U: crate::transport::ReadCancelSafety,
{
    fn read_cancel_safe(&self) -> bool {
        match self {
            Self::Tcp(t) => t.read_cancel_safe(),
            Self::Usb(u) => u.read_cancel_safe(),
        }
    }
}

/// [`NoUsb`] was chosen as the backend, so `usb://` cannot be served.
///
/// Says nothing about what the build contains: a call site may pick
/// [`NoUsb`] with both backends compiled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoBackend;

impl core::fmt::Display for NoBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no usb backend selected")
    }
}

impl core::error::Error for NoBackend {}

/// Error type of [`NoUsb`]; also has no values.
#[derive(Debug)]
pub enum NoUsbError {}

impl core::fmt::Display for NoUsbError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for NoUsbError {}

impl embedded_io::Error for NoUsbError {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

#[derive(Debug)]
pub enum TransportError<E, U> {
    Tcp(E),
    Usb(U),
}

impl<E: core::fmt::Display, U: core::fmt::Display> core::fmt::Display for TransportError<E, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tcp(e) => write!(f, "tcp: {e}"),
            Self::Usb(e) => write!(f, "usb: {e}"),
        }
    }
}

impl<E, U> core::error::Error for TransportError<E, U>
where
    E: core::error::Error + 'static,
    U: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Tcp(e) => Some(e),
            Self::Usb(e) => Some(e),
        }
    }
}

impl<E: embedded_io::Error, U: embedded_io::Error> embedded_io::Error for TransportError<E, U> {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Tcp(e) => embedded_io::Error::kind(e),
            Self::Usb(e) => embedded_io::Error::kind(e),
        }
    }
}

impl<T: ErrorType, U: ErrorType> ErrorType for Transport<T, U> {
    type Error = TransportError<T::Error, U::Error>;
}

impl<T: Read, U: Read> Read for Transport<T, U> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Tcp(t) => Read::read(t, buf).await.map_err(TransportError::Tcp),
            Self::Usb(t) => Read::read(t, buf).await.map_err(TransportError::Usb),
        }
    }
}

impl<T: Write, U: Write> Write for Transport<T, U> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Tcp(t) => Write::write(t, buf).await.map_err(TransportError::Tcp),
            Self::Usb(t) => Write::write(t, buf).await.map_err(TransportError::Usb),
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Tcp(t) => Write::flush(t).await.map_err(TransportError::Tcp),
            Self::Usb(t) => Write::flush(t).await.map_err(TransportError::Usb),
        }
    }
}

impl<T: Splittable, U: Splittable> Splittable for Transport<T, U> {
    type ReadHalf = Transport<T::ReadHalf, U::ReadHalf>;
    type WriteHalf = Transport<T::WriteHalf, U::WriteHalf>;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        match self {
            Self::Tcp(t) => {
                let (r, w) = t.split().map_err(TransportError::Tcp)?;
                Ok((Transport::Tcp(r), Transport::Tcp(w)))
            }
            Self::Usb(t) => {
                let (r, w) = t.split().map_err(TransportError::Usb)?;
                Ok((Transport::Usb(r), Transport::Usb(w)))
            }
        }
    }
}

#[cfg(feature = "tls")]
impl<T: Read + Write, U> Transport<T, U> {
    /// Wrap a TCP transport in [`MaybeTls`] so that it can start TLS
    /// later, starting none now. A USB transport passes through as it
    /// is: adbd never offers TLS there, and `start_tls` on it fails
    /// with [`TlsError::NotAvailable`], wrapped in `TransportError::Tcp`
    /// as every TLS error is.
    ///
    /// [`TlsError::NotAvailable`]: crate::transport::tls::TlsError::NotAvailable
    pub fn tls_ready(self) -> Transport<MaybeTls<T>, U> {
        match self {
            Self::Tcp(t) => Transport::Tcp(MaybeTls::plain(t)),
            Self::Usb(u) => Transport::Usb(u),
        }
    }
}
