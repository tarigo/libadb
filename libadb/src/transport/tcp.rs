//! Convenience type aliases for TCP transports with different async runtimes.

#[cfg(feature = "tokio")]
pub type TokioTcp = embedded_io_adapters::tokio_1::FromTokio<tokio::net::TcpStream>;

#[cfg(feature = "smol")]
pub type SmolTcp = embedded_io_adapters::futures_03::FromFutures<smol::net::TcpStream>;

#[cfg(feature = "tokio")]
mod tokio_split {
    use embedded_io_adapters::tokio_1::FromTokio;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpStream;

    use crate::transport::Splittable;

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

    use crate::transport::Splittable;

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
