//! TCP transports, one per runtime: the `TokioTcp` and `SmolTcp`
//! adapter aliases, and `BlockingTcp`, the socket the runtime-less
//! `Inline` dials.

#[cfg(all(test, feature = "split"))]
mod tests;

#[cfg(feature = "tokio")]
pub type TokioTcp = embedded_io_adapters::tokio_1::FromTokio<tokio::net::TcpStream>;

#[cfg(feature = "smol")]
pub type SmolTcp = embedded_io_adapters::futures_03::FromFutures<smol::net::TcpStream>;

/// A `std::net::TcpStream` driven by blocking calls: each read and
/// write parks the calling thread until the socket answers, so its
/// futures never return `Pending`. For the same reason a read in
/// flight cannot be interrupted; see
/// [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
///
/// A signal that lands during a read or write does not end it: the call
/// is made again, which also starts any socket timeout over. A timeout
/// that fires is reported as it is.
///
/// This is what [`Inline`](crate::transport::runtime::Inline) dials,
/// and it suits a blocking executor such as `libadb-ffi`'s. On an
/// async runtime it would stall the executor thread; use that
/// runtime's own TCP transport there.
///
/// Splitting clones the socket, so the halves read and write one
/// connection independently.
#[cfg(feature = "split")]
#[derive(Debug)]
pub struct BlockingTcp(std::net::TcpStream);

#[cfg(feature = "split")]
mod blocking {
    use std::io;
    use std::net::TcpStream;

    use super::BlockingTcp;
    use crate::transport::{ReadCancelSafety, Splittable};

    pub(super) fn past_signals<T>(mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        loop {
            match call() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                done => return done,
            }
        }
    }

    impl BlockingTcp {
        /// Wrap a connected socket as it is, options included: unlike
        /// a dial through `Inline`, this leaves Nagle as it finds it.
        pub fn new(stream: TcpStream) -> Self {
            Self(stream)
        }

        /// The socket underneath, for options such as timeouts.
        pub fn get_ref(&self) -> &TcpStream {
            &self.0
        }
    }

    impl embedded_io::ErrorType for BlockingTcp {
        type Error = io::Error;
    }

    impl embedded_io_async::Read for BlockingTcp {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
            past_signals(|| io::Read::read(&mut self.0, buf))
        }
    }

    impl embedded_io_async::Write for BlockingTcp {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
            past_signals(|| io::Write::write(&mut self.0, buf))
        }

        async fn flush(&mut self) -> Result<(), io::Error> {
            io::Write::flush(&mut self.0)
        }
    }

    impl ReadCancelSafety for BlockingTcp {
        fn read_cancel_safe(&self) -> bool {
            false
        }
    }

    impl Splittable for BlockingTcp {
        type ReadHalf = BlockingTcp;
        type WriteHalf = BlockingTcp;
        fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), io::Error> {
            let clone = self.0.try_clone()?;
            Ok((BlockingTcp(self.0), BlockingTcp(clone)))
        }
    }
}

#[cfg(feature = "tokio")]
mod tokio_split {
    use embedded_io_adapters::tokio_1::FromTokio;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpStream;

    use crate::transport::{ReadCancelSafety, Splittable};

    impl ReadCancelSafety for FromTokio<TcpStream> {
        fn read_cancel_safe(&self) -> bool {
            true
        }
    }

    impl ReadCancelSafety for FromTokio<OwnedReadHalf> {
        fn read_cancel_safe(&self) -> bool {
            true
        }
    }

    impl Splittable for FromTokio<TcpStream> {
        type ReadHalf = FromTokio<OwnedReadHalf>;
        type WriteHalf = FromTokio<OwnedWriteHalf>;
        fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), std::io::Error> {
            let (r, w) = self.into_inner().into_split();
            Ok((FromTokio::new(r), FromTokio::new(w)))
        }
    }
}

#[cfg(feature = "smol")]
mod smol_split {
    use embedded_io_adapters::futures_03::FromFutures;
    use smol::net::TcpStream;

    use crate::transport::{ReadCancelSafety, Splittable};

    impl ReadCancelSafety for FromFutures<TcpStream> {
        fn read_cancel_safe(&self) -> bool {
            true
        }
    }

    impl Splittable for FromFutures<TcpStream> {
        type ReadHalf = FromFutures<TcpStream>;
        type WriteHalf = FromFutures<TcpStream>;
        fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), std::io::Error> {
            let stream = self.into_inner();
            let clone = stream.clone();
            Ok((FromFutures::new(stream), FromFutures::new(clone)))
        }
    }
}
