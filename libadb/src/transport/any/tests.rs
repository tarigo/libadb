use super::{connect, AnyTransport, ConnectError};
use crate::transport::common::{NoBackend, NoUsb, Transport};
use crate::transport::runtime::Inline;
use crate::transport::uri::UriError;
use alloc::format;
use core::future::Future;
use std::io;

/// The backend under test everywhere except the `usb://` cases:
/// TCP URIs never touch it.
type NoBackendChosen = NoUsb;

/// Whichever runtime this build has; the tests do not care which. A
/// build with neither still has `Inline`.
#[cfg(feature = "tokio")]
type TestRuntime = crate::transport::runtime::Tokio;
#[cfg(all(feature = "smol", not(feature = "tokio")))]
type TestRuntime = crate::transport::runtime::Smol;
#[cfg(not(any(feature = "tokio", feature = "smol")))]
type TestRuntime = Inline;

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
    #[cfg(not(any(feature = "tokio", feature = "smol")))]
    {
        poll_once(fut)
    }
}

/// Drive an `Inline` future, which is ready at its first poll.
fn poll_once<F: Future>(fut: F) -> F::Output {
    let mut fut = core::pin::pin!(fut);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(v) => v,
        core::task::Poll::Pending => panic!("Inline never parks"),
    }
}

/// A plain socket serves every runtime: nothing here accepts, the
/// kernel completes the handshake on its own.
fn reserve_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
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
        assert_eq!(
            format!("{}", err),
            "usb: no USB backend compiled in or selected"
        );
    }
}

#[cfg(all(feature = "nusb", feature = "rusb"))]
#[test]
fn both_usb_backends_can_be_selected_in_one_build() {
    use crate::transport::{nusb::Nusb, rusb::Rusb, UsbBackend};

    // Compiling this is the assertion: two backends, one build,
    // chosen per call site rather than per feature set.
    fn takes_backend<R, B: UsbBackend<R>>() {}
    takes_backend::<TestRuntime, Nusb>();
    takes_backend::<TestRuntime, Rusb>();
}

#[test]
fn connect_tcp_to_listening_port_returns_tcp_transport() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    block_on(async {
        let port = listener.local_addr().unwrap().port();
        let uri = format!("tcp://127.0.0.1:{}", port);
        let transport = connect::<TestRuntime, NoBackendChosen>(&uri)
            .await
            .expect("connect to open port");
        assert_matches_tcp_transport(transport);
    });
}

#[test]
fn inline_connects_without_a_runtime() {
    // The path libadb-ffi takes whatever else the build carries.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("tcp://{}", listener.local_addr().unwrap());
    match poll_once(connect::<Inline, NoUsb>(&uri)) {
        Ok(Transport::Tcp(tcp)) => assert!(tcp.get_ref().nodelay().unwrap()),
        Ok(Transport::Usb(never)) => match never {},
        Err(e) => panic!("connect to open port: {e}"),
    }
    let err = match poll_once(connect::<Inline, NoUsb>("usb://")) {
        Ok(_) => panic!("NoUsb cannot serve usb://"),
        Err(e) => e,
    };
    assert!(matches!(err, ConnectError::Usb(NoBackend)), "got {err:?}");
}

#[test]
fn connect_tcp_to_closed_port_returns_tcp_io_error() {
    block_on(async {
        let port = reserve_free_port();
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
    let n = block_on(<TestRuntime as crate::transport::runtime::Runtime>::run_blocking(|| 6 * 7))
        .expect("blocking pool");
    assert_eq!(n, 42);
}
