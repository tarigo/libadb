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

use nusb::transfer::{Direction, EndpointType, RequestBuffer};
use nusb::Interface;

use crate::transport::usb::{scan, speaks_adb, Enumerated, ScanError};

/// USB transport wrapping `nusb::Interface` with bulk endpoints.
///
/// Cheap to clone — `Interface` is Arc-backed internally. Cloning
/// shares the same device handle and endpoints, which makes it safe
/// to use one clone for reading and another for writing concurrently
/// (see [`Splittable`](crate::Splittable)).
#[derive(Clone)]
pub struct UsbTransport {
    iface: Interface,
    ep_in: u8,
    ep_out: u8,
}

impl UsbTransport {
    /// Create a transport from an already-claimed `nusb::Interface`.
    ///
    /// Scans the interface's endpoints to find bulk IN and OUT.
    /// Returns `None` if the required endpoints are not found.
    pub fn new(iface: Interface) -> Option<Self> {
        let descriptors = iface.descriptors().next()?;
        let mut ep_in = None;
        let mut ep_out = None;

        for ep in descriptors.endpoints() {
            if ep.transfer_type() == EndpointType::Bulk {
                match ep.direction() {
                    Direction::In => ep_in = Some(ep.address()),
                    Direction::Out => ep_out = Some(ep.address()),
                }
            }
        }

        Some(Self {
            iface,
            ep_in: ep_in?,
            ep_out: ep_out?,
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

    /// Write to the bulk OUT endpoint.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, nusb::transfer::TransferError> {
        let data = buf.to_vec();
        let completion = self.iface.bulk_out(self.ep_out, data).await;
        completion.into_result()?;
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

// Dropping a bulk transfer discards whatever the device already
// put in it: those bytes are gone, not waiting to be re-read.
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
        embedded_io::ErrorKind::Other
    }
}

use crate::uri::UsbSelector;

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
    scan(devices, selector, |info, iface_num| {
        let device = info.open().map_err(UsbConnectError::Open)?;
        let interface = device
            .claim_interface(iface_num)
            .map_err(UsbConnectError::Claim)?;
        UsbTransport::new(interface).ok_or(UsbConnectError::NoBulkEndpoints)
    })
}

impl Enumerated for nusb::DeviceInfo {
    type Error = UsbConnectError;

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

    #[test]
    fn a_connect_error_leads_to_the_io_error_behind_it() {
        use core::error::Error as _;
        let err = UsbConnectError::Claim(std::io::Error::other("busy"));
        let source = err.source().expect("the io error is the source");
        assert_eq!(alloc::format!("{source}"), "busy");
        assert!(UsbConnectError::NotFound.source().is_none());
    }
}
