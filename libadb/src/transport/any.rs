//! Transport that unifies TCP and USB behind a single concrete type,
//! and a [`connect`] helper that builds one from a URI.
//!
//! Both halves are type parameters: the runtime comes from
//! [`Runtime`] and the USB backend
//! from [`UsbBackend`], so a build may
//! carry `tokio` and `smol`, `nusb` and `rusb`, and each call site says
//! which it wants.

#[cfg(test)]
mod tests;

use embedded_io::ErrorType;

use crate::transport::common::{NoUsb, Transport, TransportError};
use crate::transport::runtime::Runtime;
use crate::transport::UsbBackend;
use crate::uri::{self, Uri, UsbSelector};

/// TCP-or-USB transport for runtime `R`. `U` is the USB transport; it
/// defaults to [`NoUsb`] for TCP-only builds.
pub type AnyTransport<R, U = NoUsb> = Transport<<R as Runtime>::Tcp, U>;

/// Error type of [`AnyTransport`].
pub type AnyTransportError<R, U = NoUsb> =
    TransportError<<<R as Runtime>::Tcp as ErrorType>::Error, <U as ErrorType>::Error>;

/// Why [`connect`] failed. `E` is the backend's own connect error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError<E> {
    Uri(uri::UriError),
    Tcp(std::io::Error),
    Usb(E),
    /// The runtime's blocking pool failed to deliver the USB connect
    /// result — typically cancelled or panicked during shutdown.
    UsbBlockingTaskFailed,
}

impl<E: core::fmt::Display> core::fmt::Display for ConnectError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uri(e) => write!(f, "uri: {e}"),
            Self::Tcp(e) => write!(f, "tcp: {e}"),
            Self::Usb(e) => write!(f, "usb: {e}"),
            Self::UsbBlockingTaskFailed => f.write_str("usb: blocking task failed"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for ConnectError<E> {}

/// Parse `uri_str` and open a transport, dialling with runtime `R` and
/// serving `usb://` with backend `B`.
///
/// ```ignore
/// let t = any::connect::<Tokio, Nusb>("usb://18d1:4ee7").await?;
/// let t = any::connect::<Smol, NoUsb>("tcp://127.0.0.1:5555").await?;
/// ```
pub async fn connect<R, B>(
    uri_str: &str,
) -> Result<AnyTransport<R, B::Transport>, ConnectError<B::Error>>
where
    R: Runtime,
    B: UsbBackend<R>,
    B::Transport: Send + 'static,
    B::Error: Send + 'static,
{
    let uri = uri::parse(uri_str).map_err(ConnectError::Uri)?;
    match uri {
        Uri::Tcp { host, port } => R::connect_tcp(host, port)
            .await
            .map(Transport::Tcp)
            .map_err(ConnectError::Tcp),
        Uri::Usb(selector) => {
            let owned = OwnedUsbSelector::from_borrowed(selector);
            R::run_blocking(move || B::connect_by_selector(owned.as_borrowed()))
                .await
                .map_err(|_| ConnectError::UsbBlockingTaskFailed)?
                .map(Transport::Usb)
                .map_err(ConnectError::Usb)
        }
    }
}

/// Owned form of [`UsbSelector`], so the blocking pool can take it.
enum OwnedUsbSelector {
    Any,
    VidPid { vid: u16, pid: u16 },
    Serial(alloc::string::String),
}

impl OwnedUsbSelector {
    fn from_borrowed(s: UsbSelector<'_>) -> Self {
        match s {
            UsbSelector::Any => Self::Any,
            UsbSelector::VidPid { vid, pid } => Self::VidPid { vid, pid },
            UsbSelector::Serial(s) => Self::Serial(s.into()),
        }
    }

    fn as_borrowed(&self) -> UsbSelector<'_> {
        match self {
            Self::Any => UsbSelector::Any,
            Self::VidPid { vid, pid } => UsbSelector::VidPid {
                vid: *vid,
                pid: *pid,
            },
            Self::Serial(s) => UsbSelector::Serial(s),
        }
    }
}
