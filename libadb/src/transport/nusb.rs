//! ADB over USB transport.
//!
//! ADB uses USB class 0xFF (vendor-specific), subclass 0x42, protocol 0x01.
//! Communication goes through two bulk endpoints (IN and OUT).
//!
//! # Cancellation
//!
//! Dropping a read future cancels the bulk transfer, and whatever the
//! device already wrote into it is discarded rather than kept for the
//! next read — enough to take the middle out of a packet. The transport
//! says so through
//! [`ReadCancelSafety`](crate::transport::ReadCancelSafety), and
//! [`select_channel`](crate::Connection::select_channel) responds by
//! checking its interrupt between reads instead of racing it against
//! one.

use alloc::string::String;
use alloc::vec::Vec;

use nusb::transfer::{Direction, EndpointType, RequestBuffer};
use nusb::Interface;

use crate::transport::usb::{ends_on_packet_boundary, scan, speaks_adb, Enumerated, ScanError};

/// USB transport wrapping `nusb::Interface` with bulk endpoints.
///
/// Cheap to clone — `Interface` is Arc-backed internally. Cloning
/// shares the same device handle and endpoints, which makes it safe
/// to use one clone for reading and another for writing concurrently
/// (see [`Splittable`](crate::Splittable)).
///
/// [`write`](Self::write) follows a transfer that fills its last USB
/// packet with a zero-length one. adbd reads in 16 KiB requests, and
/// only a short packet completes one early, so the bytes would
/// otherwise sit on the device until the next write.
#[derive(Clone)]
pub struct UsbTransport {
    iface: Interface,
    ep_in: u8,
    ep_out: u8,
    out_packet_size: usize,
}

impl UsbTransport {
    /// Create a transport from an already-claimed `nusb::Interface`.
    ///
    /// Scans the interface's endpoints to find bulk IN and OUT, and how
    /// large a packet the OUT one takes.
    /// Returns `None` if the required endpoints are not found.
    pub fn new(iface: Interface) -> Option<Self> {
        let descriptors = iface.descriptors().next()?;
        let mut ep_in = None;
        let mut ep_out = None;

        for ep in descriptors.endpoints() {
            if ep.transfer_type() == EndpointType::Bulk {
                match ep.direction() {
                    Direction::In => ep_in = Some(ep.address()),
                    Direction::Out => ep_out = Some((ep.address(), ep.max_packet_size())),
                }
            }
        }

        let (ep_out, out_packet_size) = ep_out?;
        Some(Self {
            iface,
            ep_in: ep_in?,
            ep_out,
            out_packet_size,
        })
    }

    /// Read from the bulk IN endpoint.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, nusb::transfer::TransferError> {
        let req = RequestBuffer::new(buf.len());
        let completion = self.iface.bulk_in(self.ep_in, req).await;
        let data = completion.into_result()?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    /// Write to the bulk OUT endpoint, as one transfer and, if that
    /// fills its last packet, a zero-length one to end it. An empty
    /// `buf` sends nothing.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, nusb::transfer::TransferError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let data = buf.to_vec();
        let completion = self.iface.bulk_out(self.ep_out, data).await;
        completion.into_result()?;
        if ends_on_packet_boundary(buf.len(), self.out_packet_size) {
            let completion = self.iface.bulk_out(self.ep_out, Vec::new()).await;
            completion.into_result()?;
        }
        Ok(buf.len())
    }
}

impl embedded_io::ErrorType for UsbTransport {
    type Error = UsbError;
}

impl embedded_io_async::Read for UsbTransport {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        UsbTransport::read(self, buf)
            .await
            .map_err(UsbError::Transfer)
    }
}

impl embedded_io_async::Write for UsbTransport {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        UsbTransport::write(self, buf)
            .await
            .map_err(UsbError::Transfer)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Dropping a bulk transfer discards what the device already put
// in it, so the bytes are gone rather than waiting to be re-read.
impl crate::transport::ReadCancelSafety for UsbTransport {
    fn read_cancel_safe(&self) -> bool {
        false
    }
}

impl crate::transport::Splittable for UsbTransport {
    type ReadHalf = UsbTransport;
    type WriteHalf = UsbTransport;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), UsbError> {
        let clone = self.clone();
        Ok((self, clone))
    }
}

/// Errors from the nusb-backed USB transport.
#[derive(Debug)]
#[non_exhaustive]
pub enum UsbError {
    /// A bulk transfer failed.
    Transfer(nusb::transfer::TransferError),
}

impl core::fmt::Display for UsbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transfer(e) => write!(f, "usb: {e}"),
        }
    }
}

impl core::error::Error for UsbError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transfer(e) => Some(e),
        }
    }
}

impl embedded_io::Error for UsbError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Transfer(nusb::transfer::TransferError::Disconnected) => {
                embedded_io::ErrorKind::NotConnected
            }
            Self::Transfer(_) => embedded_io::ErrorKind::Other,
        }
    }
}

use crate::transport::uri::UsbSelector;

/// Reasons USB connect can fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum UsbConnectError {
    /// Device enumeration failed.
    Enumerate(std::io::Error),
    /// No device matched the selector.
    NotFound,
    /// Matching device has no ADB-class interface.
    NoAdbInterface,
    /// Opening the device failed.
    Open(std::io::Error),
    /// Claiming the interface failed.
    Claim(std::io::Error),
    /// The claimed interface has no bulk IN/OUT endpoints.
    NoBulkEndpoints,
}

impl core::fmt::Display for UsbConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Enumerate(e) => write!(f, "enumerate: {e}"),
            Self::NotFound => f.write_str("device not found"),
            Self::NoAdbInterface => f.write_str("no adb interface on device"),
            Self::Open(e) => write!(f, "open: {e}"),
            Self::Claim(e) => write!(f, "claim: {e}"),
            Self::NoBulkEndpoints => f.write_str("interface has no bulk endpoints"),
        }
    }
}

impl core::error::Error for UsbConnectError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Enumerate(e) | Self::Open(e) | Self::Claim(e) => Some(e),
            Self::NotFound | Self::NoAdbInterface | Self::NoBulkEndpoints => None,
        }
    }
}

/// The `nusb` backend: pure-Rust, async bulk transfers.
///
/// Zero-sized marker for [`UsbBackend`](crate::transport::UsbBackend);
/// pass it where a backend is required, e.g.
/// `any::connect::<Tokio, Nusb>("usb://")`.
pub struct Nusb;

impl<R> crate::transport::UsbBackend<R> for Nusb {
    type Transport = UsbTransport;
    type Error = UsbConnectError;

    fn connect_by_selector(selector: UsbSelector<'_>) -> Result<UsbTransport, UsbConnectError> {
        connect_by_selector(selector)
    }
}

/// Enumerate USB devices, pick one matching `selector`, claim its ADB
/// interface, and build a [`UsbTransport`].
///
/// Synchronous: `nusb` enumerate/open/claim are all blocking calls.
pub fn connect_by_selector(selector: UsbSelector<'_>) -> Result<UsbTransport, UsbConnectError> {
    let devices = nusb::list_devices().map_err(UsbConnectError::Enumerate)?;
    scan(devices.map(Ok), selector, |info, iface_num| {
        let device = info.open().map_err(UsbConnectError::Open)?;
        let interface = device
            .claim_interface(iface_num)
            .map_err(UsbConnectError::Claim)?;
        UsbTransport::new(interface).ok_or(UsbConnectError::NoBulkEndpoints)
    })
}

impl Enumerated for nusb::DeviceInfo {
    type Error = UsbConnectError;
    type Interface = u8;

    fn vid(&self) -> u16 {
        self.vendor_id()
    }

    fn pid(&self) -> u16 {
        self.product_id()
    }

    fn adb_interface(&self) -> Result<Option<u8>, UsbConnectError> {
        Ok(self.interfaces().find_map(|iface| {
            speaks_adb(iface.class(), iface.subclass(), iface.protocol())
                .then(|| iface.interface_number())
        }))
    }

    fn serial(&mut self) -> Result<Option<String>, UsbConnectError> {
        Ok(self.serial_number().map(String::from))
    }
}

impl ScanError for UsbConnectError {
    fn not_found() -> Self {
        Self::NotFound
    }

    fn no_adb_interface() -> Self {
        Self::NoAdbInterface
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_error_stays_reachable_through_the_wrapper() {
        use core::error::Error as _;
        let err = UsbError::Transfer(nusb::transfer::TransferError::Cancelled);
        let source = err.source().expect("the transfer error is the source");
        assert_eq!(
            alloc::format!("{source}"),
            alloc::format!("{}", nusb::transfer::TransferError::Cancelled)
        );
    }

    /// What the connection goes by to tell a device gone from any other
    /// failed transfer.
    #[test]
    fn a_device_gone_is_not_connected() {
        use embedded_io::{Error as _, ErrorKind};
        use nusb::transfer::TransferError;

        let kind = |e| UsbError::Transfer(e).kind();
        assert_eq!(kind(TransferError::Disconnected), ErrorKind::NotConnected);
        for other in [
            TransferError::Cancelled,
            TransferError::Stall,
            TransferError::Fault,
            TransferError::Unknown,
        ] {
            assert_eq!(kind(other), ErrorKind::Other, "{other:?}");
        }
    }

    #[test]
    fn a_connect_error_leads_to_the_io_error_behind_it() {
        use core::error::Error as _;
        let err = UsbConnectError::Claim(std::io::Error::other("busy"));
        let source = err.source().expect("the io error is the source");
        assert_eq!(alloc::format!("{source}"), "busy");
        assert!(UsbConnectError::NotFound.source().is_none());
    }
}
