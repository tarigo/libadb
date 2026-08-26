use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use std::io;
use std::net::TcpStream;

use libadb::transport::common::{Transport, TransportError};
use libadb::uri::{self, Uri};
use libadb::Splittable;

// The C ABI has a single `adb_connect(uri)`, so when both backends are
// compiled in one of them has to win: nusb, matching the `usb` alias.
#[cfg(feature = "nusb")]
use libadb::transport::nusb::{connect_by_selector, UsbConnectError};

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
use libadb::transport::rusb::{connect_by_selector, UsbConnectError};

#[cfg(feature = "nusb")]
type Usb = libadb::transport::nusb::UsbTransport;

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
type Usb = libadb::transport::rusb::UsbTransport<libadb::transport::runtime::Inline>;

#[cfg(not(any(feature = "nusb", feature = "rusb")))]
type Usb = libadb::transport::common::NoUsb;

pub(crate) struct BlockingTcp(TcpStream);

impl ErrorType for BlockingTcp {
    type Error = io::Error;
}

impl Read for BlockingTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        io::Read::read(&mut self.0, buf)
    }
}

impl Write for BlockingTcp {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        io::Write::write(&mut self.0, buf)
    }

    async fn flush(&mut self) -> Result<(), io::Error> {
        io::Write::flush(&mut self.0)
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

pub(crate) type FfiTransport = Transport<BlockingTcp, Usb>;
pub(crate) type FfiTransportError =
    TransportError<io::Error, <Usb as embedded_io::ErrorType>::Error>;

#[derive(Debug)]
pub(crate) enum FfiConnectError {
    Uri(uri::UriError),
    #[cfg_attr(any(feature = "nusb", feature = "rusb"), allow(dead_code))]
    UnsupportedScheme,
    Tcp(io::Error),
    #[cfg(any(feature = "nusb", feature = "rusb"))]
    Usb(UsbConnectError),
}

impl core::fmt::Display for FfiConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uri(e) => write!(f, "uri: {e}"),
            Self::UnsupportedScheme => f.write_str("transport not compiled in"),
            Self::Tcp(e) => write!(f, "tcp: {e}"),
            #[cfg(any(feature = "nusb", feature = "rusb"))]
            Self::Usb(e) => write!(f, "usb: {e}"),
        }
    }
}

pub(crate) fn connect(uri_str: &str) -> Result<FfiTransport, FfiConnectError> {
    let uri = uri::parse(uri_str).map_err(FfiConnectError::Uri)?;
    match uri {
        Uri::Tcp { host, port } => {
            let stream = TcpStream::connect((host, port)).map_err(FfiConnectError::Tcp)?;
            stream.set_nodelay(true).map_err(FfiConnectError::Tcp)?;
            Ok(FfiTransport::Tcp(BlockingTcp(stream)))
        }
        Uri::Usb(selector) => {
            #[cfg(any(feature = "nusb", feature = "rusb"))]
            {
                connect_by_selector(selector)
                    .map(FfiTransport::Usb)
                    .map_err(FfiConnectError::Usb)
            }
            #[cfg(not(any(feature = "nusb", feature = "rusb")))]
            {
                let _ = selector;
                Err(FfiConnectError::UnsupportedScheme)
            }
        }
    }
}
