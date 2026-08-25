//! Transport that unifies TCP and USB behind a single concrete type,
//! and a [`connect`] helper that builds one from a URI.
//!
//! Compiled when one of `tokio` / `smol` is enabled, since TCP needs an
//! async runtime. The USB half is a type parameter: pass a backend
//! marker such as `nusb::Nusb` or `rusb::Rusb`, or
//! [`NoUsb`] when a build has none —
//! then `usb://` URIs fail with [`ConnectError::Usb`] instead of not
//! compiling.

use embedded_io::ErrorType;

#[cfg(feature = "tokio")]
use crate::transport::tcp::TokioTcp;

#[cfg(feature = "smol")]
use crate::transport::tcp::SmolTcp;

use crate::transport::common::{NoUsb, Transport, TransportError};
use crate::transport::UsbBackend;
use crate::uri::{self, Uri, UsbSelector};

#[cfg(feature = "tokio")]
type Tcp = TokioTcp;
#[cfg(feature = "smol")]
type Tcp = SmolTcp;

/// TCP-or-USB transport over the compiled-in runtime. `U` is the USB
/// transport; it defaults to [`NoUsb`] for TCP-only builds.
pub type AnyTransport<U = NoUsb> = Transport<Tcp, U>;

/// Error type of [`AnyTransport`].
pub type AnyTransportError<U = NoUsb> =
    TransportError<<Tcp as ErrorType>::Error, <U as ErrorType>::Error>;

/// Why [`connect`] failed. `E` is the backend's own connect error.
#[derive(Debug)]
pub enum ConnectError<E> {
    Uri(uri::UriError),
    Tcp(std::io::Error),
    Usb(E),
    /// The runtime's blocking-task pool failed to deliver the USB
    /// connect result — typically cancelled or panicked during runtime
    /// shutdown.
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

/// Parse `uri_str` and open a transport to the referenced endpoint,
/// using `B` for `usb://` URIs.
///
/// ```ignore
/// let t = any::connect::<Nusb>("usb://18d1:4ee7").await?;
/// let t = any::connect::<NoUsb>("tcp://127.0.0.1:5555").await?;
/// ```
pub async fn connect<B>(uri_str: &str) -> Result<AnyTransport<B::Transport>, ConnectError<B::Error>>
where
    B: UsbBackend,
    B::Transport: Send + 'static,
    B::Error: Send + 'static,
{
    let uri = uri::parse(uri_str).map_err(ConnectError::Uri)?;
    match uri {
        Uri::Tcp { host, port } => {
            #[cfg(feature = "tokio")]
            {
                let stream = tokio::net::TcpStream::connect((host, port))
                    .await
                    .map_err(ConnectError::Tcp)?;
                Ok(Transport::Tcp(TokioTcp::new(stream)))
            }
            #[cfg(feature = "smol")]
            {
                let stream = smol::net::TcpStream::connect((host, port))
                    .await
                    .map_err(ConnectError::Tcp)?;
                Ok(Transport::Tcp(SmolTcp::new(stream)))
            }
        }
        Uri::Usb(selector) => {
            let owned = OwnedUsbSelector::from_borrowed(selector);
            run_blocking(move || B::connect_by_selector(owned.as_borrowed()))
                .await?
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

#[cfg(feature = "tokio")]
async fn run_blocking<T, E>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ConnectError<E>>
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

#[cfg(all(feature = "smol", not(feature = "tokio")))]
async fn run_blocking<T, E>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ConnectError<E>>
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
    use crate::transport::common::{NoBackend, NoUsb, Transport};
    use crate::uri::UriError;
    use alloc::format;
    use core::future::Future;
    use std::io;

    /// The backend under test everywhere except the `usb://` cases:
    /// TCP URIs never touch it.
    type NoBackendChosen = NoUsb;

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
            Transport::Usb(never) => match never {},
        }
    }

    fn unwrap_err<E: core::fmt::Debug>(
        r: Result<AnyTransport, ConnectError<E>>,
    ) -> ConnectError<E> {
        match r {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn connect_error_display_uri_wraps_inner() {
        let e: ConnectError<NoBackend> = ConnectError::Uri(UriError::InvalidHost);
        assert_eq!(format!("{}", e), "uri: invalid host");
    }

    #[test]
    fn connect_error_display_tcp_wraps_inner_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let e: ConnectError<NoBackend> = ConnectError::Tcp(io_err);
        assert_eq!(format!("{}", e), "tcp: refused");
    }

    #[test]
    fn connect_error_implements_std_error_trait() {
        fn takes_std_err<E: std::error::Error>(_: &E) {}
        takes_std_err(&ConnectError::<NoBackend>::UsbBlockingTaskFailed);
    }

    #[test]
    fn connect_missing_scheme_returns_uri_error() {
        let err = unwrap_err(block_on(connect::<NoBackendChosen>("127.0.0.1:5555")));
        assert!(matches!(err, ConnectError::Uri(UriError::MissingScheme)));
    }

    #[test]
    fn connect_unknown_scheme_returns_uri_error() {
        let err = unwrap_err(block_on(connect::<NoBackendChosen>("ftp://host:21")));
        assert!(matches!(err, ConnectError::Uri(UriError::UnknownScheme)));
    }

    #[test]
    fn connect_malformed_tcp_uri_returns_uri_error() {
        let err = unwrap_err(block_on(connect::<NoBackendChosen>("tcp://host")));
        assert!(matches!(err, ConnectError::Uri(UriError::InvalidPort)));
    }

    #[test]
    fn connect_usb_without_a_backend_reports_it_at_runtime() {
        // The point of NoUsb: `usb://` still compiles, and fails with a
        // clear error instead of a missing feature.
        for uri in ["usb://", "usb://18d1:4ee7", "usb://serial/ABC123"] {
            let err = unwrap_err(block_on(connect::<NoUsb>(uri)));
            assert!(
                matches!(err, ConnectError::Usb(NoBackend)),
                "{uri}: got {err:?}",
            );
            assert_eq!(format!("{}", err), "usb: no usb backend compiled in");
        }
    }

    #[cfg(all(feature = "nusb", feature = "rusb"))]
    #[test]
    fn both_usb_backends_can_be_selected_in_one_build() {
        use crate::transport::{nusb::Nusb, rusb::Rusb, UsbBackend};

        // Compiling this is the assertion: two backends, one build,
        // chosen per call site rather than per feature set.
        fn takes_backend<B: UsbBackend>() {}
        takes_backend::<Nusb>();
        takes_backend::<Rusb>();
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
            let transport = connect::<NoBackendChosen>(&uri)
                .await
                .expect("connect to open port");
            assert_matches_tcp_transport(transport);
            drop(listener);
        });
    }

    #[test]
    fn connect_tcp_to_closed_port_returns_tcp_io_error() {
        block_on(async {
            let port = reserve_free_port().await;
            let uri = format!("tcp://127.0.0.1:{}", port);
            let err = connect::<NoBackendChosen>(&uri)
                .await
                .err()
                .expect("connect to closed port");
            assert!(matches!(err, ConnectError::Tcp(_)));
        });
    }
}
