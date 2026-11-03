use embedded_io::ErrorType;
use std::net::TcpStream;

use libadb::transport::any::{self, ConnectError};
use libadb::transport::common::Transport;
use libadb::transport::runtime::Inline;
use libadb::transport::tcp::BlockingTcp;
use libadb::transport::UsbBackend;

// The C ABI has a single `adb_connect(uri)`, so when both backends are
// compiled in one of them has to win: nusb, matching the `usb` alias.
#[cfg(feature = "nusb")]
type Backend = libadb::transport::nusb::Nusb;

#[cfg(all(feature = "rusb", not(feature = "nusb")))]
type Backend = libadb::transport::rusb::Rusb;

#[cfg(not(any(feature = "nusb", feature = "rusb")))]
type Backend = libadb::transport::common::NoUsb;

type Usb = <Backend as UsbBackend<Inline>>::Transport;

/// The TCP half: able to start TLS when the build can answer STLS.
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

/// Open the transport `uri` names. Over `tcp://` a second handle to the
/// socket comes along, for socket options: `MaybeTls` keeps its stream
/// to itself, so the clone is taken before wrapping. A clone failure
/// fails the connect rather than producing a connection whose timeout
/// setter claims there is no socket.
pub(crate) fn connect(uri: &str) -> Result<(FfiTransport, Option<TcpStream>), FfiConnectError> {
    match crate::block_on::block_on(any::connect::<Inline, Backend>(uri))? {
        Transport::Tcp(plain) => {
            let socket = plain.get_ref().try_clone().map_err(ConnectError::Tcp)?;
            Ok((Transport::Tcp(tcp(plain)), Some(socket)))
        }
        Transport::Usb(usb) => Ok((Transport::Usb(usb), None)),
    }
}
