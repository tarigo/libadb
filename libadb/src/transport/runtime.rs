//! The async runtime as a type parameter rather than a feature.
//!
//! TCP needs a runtime to dial a socket, and the blocking USB backends
//! need somewhere to park a synchronous call. Both are chosen per call
//! site through [`Runtime`], so enabling both `tokio` and `smol`
//! compiles, and two crates in one dependency tree can ask for
//! different ones.
//!
//! [`Inline`] covers builds with no runtime at all: it dials TCP and
//! runs blocking work on the calling thread.

use core::future::Future;

use crate::transport::tcp::BlockingTcp;
use crate::transport::Splittable;

/// An async runtime libadb can drive TCP and blocking work on.
///
/// Implemented by [`Inline`], which needs no runtime, and by the
/// zero-sized markers `Tokio` and `Smol`, each behind its own feature.
///
/// Every method returns `impl Future + Send` rather than being an
/// `async fn`, so generic callers keep the `Send` bound they need to
/// spawn the resulting future.
pub trait Runtime {
    /// TCP transport this runtime produces.
    type Tcp: Splittable + Send + 'static;

    /// Dial `host:port`.
    ///
    /// Implementations disable Nagle (`TCP_NODELAY`), as `adb` itself
    /// does: the protocol answers small packets with small packets, and
    /// coalescing them costs a delayed-ACK round on every exchange.
    fn connect_tcp(
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Self::Tcp, std::io::Error>> + Send;

    /// Run a blocking closure without stalling the executor.
    ///
    /// Used for USB enumeration, which is synchronous in both backends.
    /// Implementations that find themselves outside their runtime may
    /// run `f` inline.
    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
}

/// The runtime's blocking pool failed to deliver a result — typically
/// cancelled or panicked during shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingError;

impl core::fmt::Display for BlockingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("blocking task failed")
    }
}

impl core::error::Error for BlockingError {}

/// Runs blocking work, and dials TCP, on the calling thread.
///
/// The fallback for builds with no async runtime — `libadb-ffi` drives
/// its transports on a blocking executor, where offloading would be
/// pointless. Its TCP transport is [`BlockingTcp`], whose reads and
/// writes block as well. A `rusb` transport can name it the same way
/// (`UsbTransport<Inline>`); nothing defaults to it.
pub struct Inline;

#[allow(clippy::manual_async_fn)]
impl Runtime for Inline {
    type Tcp = BlockingTcp;

    fn connect_tcp(
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Self::Tcp, std::io::Error>> + Send {
        let host = alloc::string::String::from(host);
        async move {
            let stream = std::net::TcpStream::connect((host.as_str(), port))?;
            stream.set_nodelay(true)?;
            Ok(BlockingTcp::new(stream))
        }
    }

    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async move { Ok(f()) }
    }
}

/// The `tokio` runtime.
#[cfg(feature = "tokio")]
pub struct Tokio;

#[allow(clippy::manual_async_fn)]
#[cfg(feature = "tokio")]
impl Runtime for Tokio {
    type Tcp = crate::transport::tcp::TokioTcp;

    fn connect_tcp(
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Self::Tcp, std::io::Error>> + Send {
        let host = alloc::string::String::from(host);
        async move {
            let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            stream.set_nodelay(true)?;
            Ok(crate::transport::tcp::TokioTcp::new(stream))
        }
    }

    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async move {
            let Ok(handle) = tokio::runtime::Handle::try_current() else {
                return Ok(f());
            };
            handle.spawn_blocking(f).await.map_err(|e| {
                log::warn!("tokio blocking task failed: {e}");
                BlockingError
            })
        }
    }
}

/// The `smol` runtime.
#[cfg(feature = "smol")]
pub struct Smol;

#[allow(clippy::manual_async_fn)]
#[cfg(feature = "smol")]
impl Runtime for Smol {
    type Tcp = crate::transport::tcp::SmolTcp;

    fn connect_tcp(
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Self::Tcp, std::io::Error>> + Send {
        let host = alloc::string::String::from(host);
        async move {
            let stream = smol::net::TcpStream::connect((host.as_str(), port)).await?;
            stream.set_nodelay(true)?;
            Ok(crate::transport::tcp::SmolTcp::new(stream))
        }
    }

    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async move {
            match smol::unblock(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))).await
            {
                Ok(t) => Ok(t),
                Err(_) => {
                    log::warn!("smol blocking task panicked");
                    Err(BlockingError)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(v) => v,
            core::task::Poll::Pending => panic!("Inline never parks"),
        }
    }

    #[test]
    fn inline_runs_the_closure_on_this_thread() {
        let here = std::thread::current().id();
        let ran_on = block_on(Inline::run_blocking(std::thread::current)).unwrap();
        assert_eq!(ran_on.id(), here);
    }

    #[test]
    fn a_blocking_failure_says_what_it_was() {
        assert_eq!(
            std::format!("{BlockingError}"),
            "blocking task failed",
            "the message is what a caller sees when a pool drops the work"
        );
    }

    #[test]
    fn inline_defers_the_closure_until_the_future_is_polled() {
        use core::sync::atomic::{AtomicBool, Ordering};
        let ran = std::sync::Arc::new(AtomicBool::new(false));
        let fut = Inline::run_blocking({
            let ran = ran.clone();
            move || ran.store(true, Ordering::SeqCst)
        });
        assert!(!ran.load(Ordering::SeqCst), "ran before the first poll");
        block_on(fut).unwrap();
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn inline_dials_tcp_with_nagle_off() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let tcp = block_on(Inline::connect_tcp("127.0.0.1", port)).unwrap();
        assert_eq!(tcp.get_ref().peer_addr().unwrap().port(), port);
        assert!(
            tcp.get_ref().nodelay().unwrap(),
            "Nagle would hold every small packet back for an ACK"
        );
    }

    #[test]
    fn inline_reports_a_refused_dial() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let err = block_on(Inline::connect_tcp("127.0.0.1", port)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn inline_defers_the_dial_until_the_future_is_polled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let fut = Inline::connect_tcp("127.0.0.1", port);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "dialled before the first poll"
        );
        let _tcp = block_on(fut).unwrap();
        assert!(listener.accept().is_ok());
    }

    #[cfg(all(feature = "tokio", feature = "smol"))]
    #[test]
    fn every_runtime_marker_is_usable_in_one_build() {
        fn takes<R: Runtime>() {}
        takes::<Tokio>();
        takes::<Smol>();
        takes::<Inline>();
    }
}
