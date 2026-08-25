//! The async runtime as a type parameter rather than a feature.
//!
//! TCP needs a runtime to dial a socket, and the blocking USB backends
//! need somewhere to park a synchronous call. Both used to be picked by
//! `cfg`, which made `tokio` and `smol` mutually exclusive: two crates
//! in one dependency tree could not ask for different ones. They are
//! now chosen per call site through [`Runtime`], so enabling both
//! features compiles and each caller says which one it means.

use core::future::Future;

use crate::transport::Splittable;

/// An async runtime libadb can drive TCP and blocking work on.
///
/// Implemented by the zero-sized markers `Tokio` and `Smol`, each
/// behind its own feature. Plain code spans rather than links on
/// purpose: a doc build with only one runtime enabled cannot resolve
/// the other.
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

/// The `tokio` runtime.
#[cfg(feature = "tokio")]
pub struct Tokio;

// `async fn` in a trait impl would drop the `Send` bound the trait
// promises, and generic callers need it to spawn the future. Hence the
// explicit `impl Future + Send` here.
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

// `async fn` in a trait impl would drop the `Send` bound the trait
// promises, and generic callers need it to spawn the future. Hence the
// explicit `impl Future + Send` here.
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
