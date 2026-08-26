//! The async runtime as a type parameter rather than a feature.
//!
//! TCP needs a runtime to dial a socket, and the blocking USB backends
//! need somewhere to park a synchronous call. Both used to be picked by
//! `cfg`, which made `tokio` and `smol` mutually exclusive: two crates
//! in one dependency tree could not ask for different ones. They are
//! now chosen per call site through [`Runtime`], so enabling both
//! features compiles and each caller says which one it means.
//!
//! [`Inline`] covers builds with no runtime at all: it runs blocking
//! work on the calling thread and cannot dial TCP.

use core::future::Future;

use crate::transport::Splittable;

/// An async runtime libadb can drive TCP and blocking work on.
///
/// Implemented by the zero-sized markers `Tokio` and `Smol`, each
/// behind its own feature. Plain code spans rather than links on
/// purpose: a doc build with only one runtime enabled cannot resolve
/// the other.
///
/// Every method returns `impl Future + Send` rather than being an
/// `async fn`, so generic callers keep the `Send` bound they need to
/// spawn the resulting future.
pub trait Runtime {
    /// TCP transport this runtime produces.
    type Tcp: Splittable + Send + 'static;

    /// Dial `host:port`.
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

/// Runs blocking work on the calling thread.
///
/// The fallback for builds with no async runtime — `libadb-ffi` drives
/// its transports on a blocking executor, where offloading would be
/// pointless. A `rusb` transport can name it the same way
/// (`UsbTransport<Inline>`); nothing defaults to it.
pub struct Inline;

#[allow(clippy::manual_async_fn)]
impl Runtime for Inline {
    type Tcp = NoTcp;

    fn connect_tcp(
        _host: &str,
        _port: u16,
    ) -> impl Future<Output = Result<Self::Tcp, std::io::Error>> + Send {
        core::future::ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Inline cannot dial TCP: pick a runtime such as Tokio or Smol",
        )))
    }

    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Deferred like the other runtimes: a future nobody polls must
        // not have run the closure.
        async move { Ok(f()) }
    }
}

/// TCP half of [`Inline`]: no values, so it can never be dialled.
#[derive(Debug)]
pub enum NoTcp {}

impl embedded_io::ErrorType for NoTcp {
    type Error = crate::transport::common::NoUsbError;
}

impl embedded_io_async::Read for NoTcp {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        match *self {}
    }
}

impl embedded_io_async::Write for NoTcp {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        match *self {}
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match *self {}
    }
}

impl Splittable for NoTcp {
    type ReadHalf = NoTcp;
    type WriteHalf = NoTcp;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        match self {}
    }
}

// `Transport<T, U>` asks both alternatives, so a USB-only build needs
// this the same way NoUsb provides it for the TCP-only one.
impl crate::transport::ReadCancelSafety for NoTcp {
    fn read_cancel_safe(&self) -> bool {
        match *self {}
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
            Ok(crate::transport::tcp::TokioTcp::new(stream))
        }
    }

    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async move {
            // Outside a tokio runtime `spawn_blocking` would panic — run
            // inline instead, blocking the caller.
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
            Ok(crate::transport::tcp::SmolTcp::new(stream))
        }
    }

    fn run_blocking<T, F>(f: F) -> impl Future<Output = Result<T, BlockingError>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async move {
            // smol re-raises panics on await; catch them so a misbehaving
            // backend maps to `BlockingError` instead of unwinding through
            // the caller.
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
    fn inline_cannot_dial_tcp() {
        let err = block_on(Inline::connect_tcp("127.0.0.1", 5555)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
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
