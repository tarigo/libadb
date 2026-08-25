//! Transport that unifies TCP and USB behind a single concrete type,
//! and a [`connect`] helper that builds one from a URI.
//!
//! Both halves are type parameters: the runtime comes from
//! [`Runtime`] and the USB backend
//! from [`UsbBackend`], so a build may
//! carry `tokio` and `smol`, `nusb` and `rusb`, and each call site says
//! which it wants.

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
    B: UsbBackend,
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

    /// Whichever runtime this build has; the tests do not care which.
    #[cfg(feature = "tokio")]
    type TestRuntime = crate::transport::runtime::Tokio;
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    type TestRuntime = crate::transport::runtime::Smol;

    fn block_on<F: Future>(fut: F) -> F::Output {
        #[cfg(feature = "tokio")]
        {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(fut)
        }
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
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
        #[cfg(all(feature = "smol", not(feature = "tokio")))]
        {
            let l = smol::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        }
    }

    fn assert_matches_tcp_transport(t: AnyTransport<TestRuntime>) {
        match t {
            Transport::Tcp(_) => {}
            Transport::Usb(never) => match never {},
        }
    }

    fn unwrap_err<E: core::fmt::Debug>(
        r: Result<AnyTransport<TestRuntime>, ConnectError<E>>,
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
        let err = unwrap_err(block_on(connect::<TestRuntime, NoBackendChosen>(
            "127.0.0.1:5555",
        )));
        assert!(matches!(err, ConnectError::Uri(UriError::MissingScheme)));
    }

    #[test]
    fn connect_unknown_scheme_returns_uri_error() {
        let err = unwrap_err(block_on(connect::<TestRuntime, NoBackendChosen>(
            "ftp://host:21",
        )));
        assert!(matches!(err, ConnectError::Uri(UriError::UnknownScheme)));
    }

    #[test]
    fn connect_malformed_tcp_uri_returns_uri_error() {
        let err = unwrap_err(block_on(connect::<TestRuntime, NoBackendChosen>(
            "tcp://host",
        )));
        assert!(matches!(err, ConnectError::Uri(UriError::InvalidPort)));
    }

    #[test]
    fn connect_usb_without_a_backend_reports_it_at_runtime() {
        // The point of NoUsb: `usb://` still compiles, and fails with a
        // clear error instead of a missing feature.
        for uri in ["usb://", "usb://18d1:4ee7", "usb://serial/ABC123"] {
            let err = unwrap_err(block_on(connect::<TestRuntime, NoUsb>(uri)));
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
            #[cfg(all(feature = "smol", not(feature = "tokio")))]
            let listener = smol::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

            let port = listener.local_addr().unwrap().port();
            let uri = format!("tcp://127.0.0.1:{}", port);
            let transport = connect::<TestRuntime, NoBackendChosen>(&uri)
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
            let err = connect::<TestRuntime, NoBackendChosen>(&uri)
                .await
                .err()
                .expect("connect to closed port");
            assert!(matches!(err, ConnectError::Tcp(_)));
        });
    }

    #[cfg(all(feature = "tokio", feature = "smol"))]
    #[test]
    fn both_runtimes_can_be_selected_in_one_build() {
        use crate::transport::runtime::{Runtime, Smol, Tokio};

        // Compiling this is the assertion: two runtimes, one build,
        // chosen per call site rather than per feature set.
        fn takes_runtime<R: Runtime>() {}
        takes_runtime::<Tokio>();
        takes_runtime::<Smol>();
    }

    #[test]
    fn run_blocking_delivers_the_closure_result() {
        let n =
            block_on(<TestRuntime as crate::transport::runtime::Runtime>::run_blocking(|| 6 * 7))
                .expect("blocking pool");
        assert_eq!(n, 42);
    }
}
