/// ADB over USB transport.
///
/// ADB uses USB class 0xFF (vendor-specific), subclass 0x42, protocol 0x01.
/// Communication goes through two bulk endpoints (IN and OUT).
#[cfg(feature = "nusb")]
pub use self::inner::*;

#[cfg(feature = "nusb")]
mod inner {
    use nusb::transfer::{Direction, EndpointType, RequestBuffer};
    use nusb::Interface;

    use crate::transport::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};

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
        pub async fn read(
            &mut self,
            buf: &mut [u8],
        ) -> Result<usize, nusb::transfer::TransferError> {
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
            UsbTransport::read(self, buf).await.map_err(UsbError)
        }
    }

    impl embedded_io_async::Write for UsbTransport {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            UsbTransport::write(self, buf).await.map_err(UsbError)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
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

    /// Wrapper around `nusb::transfer::TransferError` implementing `embedded_io::Error`.
    #[derive(Debug)]
    pub struct UsbError(pub nusb::transfer::TransferError);

    impl core::fmt::Display for UsbError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "usb: {}", self.0)
        }
    }

    impl core::error::Error for UsbError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            Some(&self.0)
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

        for info in devices {
            let matches = match selector {
                UsbSelector::Any => true,
                UsbSelector::VidPid { vid, pid } => {
                    info.vendor_id() == vid && info.product_id() == pid
                }
                UsbSelector::Serial(s) => info.serial_number() == Some(s),
            };
            if !matches {
                continue;
            }

            let iface_num = info.interfaces().find_map(|iface| {
                (iface.class() == ADB_CLASS
                    && iface.subclass() == ADB_SUBCLASS
                    && iface.protocol() == ADB_PROTOCOL)
                    .then(|| iface.interface_number())
            });
            let Some(iface_num) = iface_num else {
                return Err(UsbConnectError::NoAdbInterface);
            };

            let device = info.open().map_err(UsbConnectError::Open)?;
            let interface = device
                .claim_interface(iface_num)
                .map_err(UsbConnectError::Claim)?;
            return UsbTransport::new(interface).ok_or(UsbConnectError::NoBulkEndpoints);
        }

        Err(UsbConnectError::NotFound)
    }
}
