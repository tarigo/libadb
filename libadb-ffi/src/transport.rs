use embedded_io::ErrorType;
use std::net::TcpStream;

use libadb::transport::any::{self, ConnectError};
use libadb::transport::common::Transport;
use libadb::transport::runtime::Inline;
use libadb::transport::tcp::BlockingTcp;
use libadb::transport::UsbBackend;

#[cfg(feature = "nusb")]
type Backend = libadb::transport::nusb::Nusb;

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
type Backend = libadb::transport::rusb::Rusb;

#[cfg(not(any(feature = "nusb", feature = "rusb")))]
type Backend = libadb::transport::common::NoUsb;

type Usb = <Backend as UsbBackend<Inline>>::Transport;

#[cfg(feature = "tls")]
pub(crate) type FfiTcp = libadb::transport::tls::MaybeTls<BlockingTcp>;
#[cfg(not(feature = "tls"))]
pub(crate) type FfiTcp = BlockingTcp;

pub(crate) type FfiTransport = Transport<FfiTcp, Usb>;
pub(crate) type FfiTransportError = <FfiTransport as ErrorType>::Error;
pub(crate) type FfiConnectError = ConnectError<<Backend as UsbBackend<Inline>>::Error>;

fn tcp(plain: BlockingTcp) -> FfiTcp {
    #[cfg(feature = "tls")]
    {
        libadb::transport::tls::MaybeTls::plain(plain)
    }
    #[cfg(not(feature = "tls"))]
    {
        plain
    }
}

pub(crate) fn connect(uri: &str) -> Result<(FfiTransport, Option<TcpStream>), FfiConnectError> {
    match crate::block_on::block_on(any::connect::<Inline, Backend>(uri))? {
        Transport::Tcp(plain) => {
            let socket = plain.get_ref().try_clone().map_err(ConnectError::Tcp)?;
            Ok((Transport::Tcp(tcp(plain)), Some(socket)))
        }
        Transport::Usb(usb) => Ok((Transport::Usb(usb), None)),
    }
}
