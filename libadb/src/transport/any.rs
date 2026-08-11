//! Runtime-polymorphic transport that unifies TCP and USB behind a
//! single concrete type, and a [`connect`] helper that builds one from
//! a URI.
//!
//! `AnyTransport` is compiled when one of `tokio` / `smol` is enabled
//! (TCP requires an async runtime), optionally combined with a USB
//! backend (`nusb` or `rusb`). The `tokio` and `smol` features are
//! mutually exclusive — enabling both fails at compile time. [`connect`]
//! returns [`ConnectError::UnsupportedScheme`] for `usb://` URIs when no
//! USB backend is compiled in.

use embedded_io::ErrorType;

#[cfg(feature = "tokio")]
use crate::transport::tcp::TokioTcp;

#[cfg(feature = "smol")]
use crate::transport::tcp::SmolTcp;

#[cfg(feature = "nusb")]
use crate::transport::nusb::{connect_by_selector, UsbConnectError};

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
use crate::transport::rusb::{connect_by_selector, UsbConnectError};

use crate::transport::common::{Transport, TransportError};
use crate::uri::{self, Uri};

#[cfg(feature = "_usb")]
use crate::uri::UsbSelector;

#[cfg(feature = "tokio")]
type Tcp = TokioTcp;
#[cfg(feature = "smol")]
type Tcp = SmolTcp;

pub type AnyTransport = Transport<Tcp>;

pub type AnyTransportError = TransportError<<Tcp as ErrorType>::Error>;

#[derive(Debug)]
pub enum ConnectError {
    Uri(uri::UriError),
    /// URI scheme recognised but its transport feature is disabled at
    /// compile time (e.g. `usb://…` without any USB backend enabled).
    UnsupportedScheme,
    Tcp(std::io::Error),
    #[cfg(feature = "_usb")]
    Usb(UsbConnectError),
    /// The runtime's blocking-task pool failed to deliver the USB
    /// connect result — typically cancelled or panicked during runtime
    /// shutdown.
    #[cfg(feature = "_usb")]
    UsbBlockingTaskFailed,
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uri(e) => write!(f, "uri: {e}"),
            Self::UnsupportedScheme => f.write_str("transport not compiled in"),
            Self::Tcp(e) => write!(f, "tcp: {e}"),
            #[cfg(feature = "_usb")]
            Self::Usb(e) => write!(f, "usb: {e}"),
            #[cfg(feature = "_usb")]
            Self::UsbBlockingTaskFailed => f.write_str("usb: blocking task failed"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Parse `uri_str` and open a transport to the referenced endpoint.
pub async fn connect(uri_str: &str) -> Result<AnyTransport, ConnectError> {
    let uri = uri::parse(uri_str).map_err(ConnectError::Uri)?;
    match uri {
        Uri::Tcp { host, port } => {
            #[cfg(feature = "tokio")]
            {
                let stream = tokio::net::TcpStream::connect((host, port))
                    .await
                    .map_err(ConnectError::Tcp)?;
                Ok(AnyTransport::Tcp(TokioTcp::new(stream)))
            }
            #[cfg(feature = "smol")]
            {
                let stream = smol::net::TcpStream::connect((host, port))
                    .await
                    .map_err(ConnectError::Tcp)?;
                Ok(AnyTransport::Tcp(SmolTcp::new(stream)))
            }
        }
        Uri::Usb(selector) => {
            #[cfg(feature = "_usb")]
            {
                usb_connect_blocking(OwnedUsbSelector::from_borrowed(selector)).await
            }
            #[cfg(not(feature = "_usb"))]
            {
                let _ = selector;
                Err(ConnectError::UnsupportedScheme)
            }
        }
    }
}

#[cfg(feature = "_usb")]
enum OwnedUsbSelector {
    Any,
    VidPid { vid: u16, pid: u16 },
    Serial(alloc::string::String),
}

#[cfg(feature = "_usb")]
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

#[cfg(feature = "_usb")]
async fn usb_connect_blocking(owned: OwnedUsbSelector) -> Result<AnyTransport, ConnectError> {
    run_blocking(move || connect_by_selector(owned.as_borrowed()))
        .await?
        .map(AnyTransport::Usb)
        .map_err(ConnectError::Usb)
}

#[cfg(all(feature = "_usb", feature = "tokio"))]
async fn run_blocking<T>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ConnectError>
where
    T: Send + 'static,
{
    // Outside a tokio runtime `spawn_blocking` would panic — run
    // inline instead, blocking the caller.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Ok(f());
    };
    handle.spawn_blocking(f).await.map_err(|e| {
        log::warn!("usb connect blocking task failed: {e}");
        ConnectError::UsbBlockingTaskFailed
    })
}

#[cfg(all(feature = "_usb", feature = "smol", not(feature = "tokio")))]
async fn run_blocking<T>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ConnectError>
where
    T: Send + 'static,
{
    // smol re-raises panics on await; catch them so libusb
    // misbehaviour maps to `UsbBlockingTaskFailed` — symmetric with
    // the tokio branch's `JoinError` handling above.
    match smol::unblock(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))).await {
        Ok(t) => Ok(t),
        Err(_) => {
            log::warn!("usb connect blocking task panicked");
            Err(ConnectError::UsbBlockingTaskFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{connect, AnyTransport, ConnectError};
    use crate::transport::common::Transport;
    use crate::uri::UriError;
    use alloc::format;
    use core::future::Future;
    use std::io;

    fn block_on<F: Future>(fut: F) -> F::Output {
        #[cfg(feature = "tokio")]
        {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(fut)
        }
        #[cfg(feature = "smol")]
        {
            smol::block_on(fut)
        }
    }

    async fn reserve_free_port() -> u16 {
        #[cfg(feature = "tokio")]
        {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        }
        #[cfg(feature = "smol")]
        {
            let l = smol::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        }
    }

    fn assert_matches_tcp_transport(t: AnyTransport) {
        match t {
            Transport::Tcp(_) => {}
            #[cfg(feature = "_usb")]
            Transport::Usb(_) => panic!("expected Tcp transport, got Usb"),
        }
    }

    fn unwrap_err(r: Result<AnyTransport, ConnectError>) -> ConnectError {
        match r {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn connect_error_display_uri_wraps_inner() {
        let e = ConnectError::Uri(UriError::InvalidHost);
        assert_eq!(format!("{}", e), "uri: invalid host");
    }

    #[test]
    fn connect_error_display_unsupported_scheme_is_static_message() {
        let e = ConnectError::UnsupportedScheme;
        assert_eq!(format!("{}", e), "transport not compiled in");
    }

    #[test]
    fn connect_error_display_tcp_wraps_inner_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let e = ConnectError::Tcp(io_err);
        assert_eq!(format!("{}", e), "tcp: refused");
    }

    #[test]
    fn connect_error_implements_std_error_trait() {
        fn takes_std_err<E: std::error::Error>(_: &E) {}
        takes_std_err(&ConnectError::UnsupportedScheme);
    }

    #[test]
    fn connect_missing_scheme_returns_uri_error() {
        let err = unwrap_err(block_on(connect("127.0.0.1:5555")));
        assert!(matches!(err, ConnectError::Uri(UriError::MissingScheme)));
    }

    #[test]
    fn connect_unknown_scheme_returns_uri_error() {
        let err = unwrap_err(block_on(connect("ftp://host:21")));
        assert!(matches!(err, ConnectError::Uri(UriError::UnknownScheme)));
    }

    #[test]
    fn connect_malformed_tcp_uri_returns_uri_error() {
        let err = unwrap_err(block_on(connect("tcp://host")));
        assert!(matches!(err, ConnectError::Uri(UriError::InvalidPort)));
    }

    #[cfg(not(feature = "_usb"))]
    #[test]
    fn connect_usb_any_without_usb_feature_returns_unsupported_scheme() {
        let err = unwrap_err(block_on(connect("usb://")));
        assert!(matches!(err, ConnectError::UnsupportedScheme));
    }

    #[cfg(not(feature = "_usb"))]
    #[test]
    fn connect_usb_vidpid_without_usb_feature_returns_unsupported_scheme() {
        let err = unwrap_err(block_on(connect("usb://18d1:4ee7")));
        assert!(matches!(err, ConnectError::UnsupportedScheme));
    }

    #[cfg(not(feature = "_usb"))]
    #[test]
    fn connect_usb_serial_without_usb_feature_returns_unsupported_scheme() {
        let err = unwrap_err(block_on(connect("usb://serial/ABC123")));
        assert!(matches!(err, ConnectError::UnsupportedScheme));
    }

    #[test]
    fn connect_tcp_to_listening_port_returns_tcp_transport() {
        block_on(async {
            #[cfg(feature = "tokio")]
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "smol")]
            let listener = smol::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

            let port = listener.local_addr().unwrap().port();
            let uri = format!("tcp://127.0.0.1:{}", port);
            let transport = connect(&uri).await.expect("connect to open port");
            assert_matches_tcp_transport(transport);
            drop(listener);
        });
    }

    #[test]
    fn connect_tcp_to_closed_port_returns_tcp_io_error() {
        block_on(async {
            let port = reserve_free_port().await;
            let uri = format!("tcp://127.0.0.1:{}", port);
            let err = connect(&uri).await.err().expect("connect to closed port");
            assert!(matches!(err, ConnectError::Tcp(_)));
        });
    }
}
