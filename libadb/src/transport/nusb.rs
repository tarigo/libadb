/// ADB over USB transport.
///
/// ADB uses USB class 0xFF (vendor-specific), subclass 0x42, protocol 0x01.
/// Communication goes through two bulk endpoints (IN and OUT).
///
/// # Cancellation
///
/// Dropping a read future cancels the bulk transfer, and whatever the
/// device already wrote into it is discarded rather than kept for the
/// next read — enough to take the middle out of a packet. The transport
/// says so through
/// [`ReadCancelSafety`](crate::transport::ReadCancelSafety), and
/// [`select_channel`](crate::Connection::select_channel) responds by
/// checking its interrupt between reads instead of racing it against
/// one.
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
        scan(devices, selector, |info, iface_num| {
            let device = info.open().map_err(UsbConnectError::Open)?;
            let interface = device
                .claim_interface(iface_num)
                .map_err(UsbConnectError::Claim)?;
            UsbTransport::new(interface).ok_or(UsbConnectError::NoBulkEndpoints)
        })
    }

    /// What device selection needs to know about one enumerated device.
    ///
    /// Exists so the scan can be exercised without a USB bus.
    trait Enumerated {
        fn vid(&self) -> u16;
        fn pid(&self) -> u16;
        fn serial(&self) -> Option<&str>;
        fn adb_interface(&self) -> Option<u8>;
    }

    impl Enumerated for nusb::DeviceInfo {
        fn vid(&self) -> u16 {
            self.vendor_id()
        }

        fn pid(&self) -> u16 {
            self.product_id()
        }

        fn serial(&self) -> Option<&str> {
            self.serial_number()
        }

        fn adb_interface(&self) -> Option<u8> {
            self.interfaces().find_map(|iface| {
                (iface.class() == ADB_CLASS
                    && iface.subclass() == ADB_SUBCLASS
                    && iface.protocol() == ADB_PROTOCOL)
                    .then(|| iface.interface_number())
            })
        }
    }

    /// Walk `devices`, handing the first one the selector accepts to
    /// `open`, and keep walking if that one turns out unusable.
    ///
    /// A VID:PID names one device, so its failures are reported as they
    /// happen. `Any` and a serial number describe a search: a device
    /// that speaks no ADB, or refuses to open, is passed over, and the
    /// first failure is only reported if nothing else works out. Without
    /// that, a hub or a webcam enumerated ahead of the phone ends the
    /// search — which is what this backend used to do.
    fn scan<D, T, F>(
        devices: impl IntoIterator<Item = D>,
        selector: UsbSelector<'_>,
        mut open: F,
    ) -> Result<T, UsbConnectError>
    where
        D: Enumerated,
        F: FnMut(D, u8) -> Result<T, UsbConnectError>,
    {
        let named = matches!(selector, UsbSelector::VidPid { .. });
        let mut first_err = None;

        for device in devices {
            let matches = match selector {
                UsbSelector::Any => true,
                UsbSelector::VidPid { vid, pid } => device.vid() == vid && device.pid() == pid,
                UsbSelector::Serial(s) => device.serial() == Some(s),
            };
            if !matches {
                continue;
            }

            let Some(iface_num) = device.adb_interface() else {
                if named {
                    return Err(UsbConnectError::NoAdbInterface);
                }
                continue;
            };

            match open(device, iface_num) {
                Ok(transport) => return Ok(transport),
                Err(e) if named => return Err(e),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }

        Err(first_err.unwrap_or(UsbConnectError::NotFound))
    }

    #[cfg(test)]
    mod tests {
        use alloc::vec;
        use alloc::vec::Vec;

        use super::*;

        struct Dev {
            vid: u16,
            pid: u16,
            serial: Option<&'static str>,
            adb: Option<u8>,
        }

        impl Dev {
            fn new(vid: u16, pid: u16, adb: Option<u8>) -> Self {
                Self {
                    vid,
                    pid,
                    serial: None,
                    adb,
                }
            }

            fn with_serial(mut self, serial: &'static str) -> Self {
                self.serial = Some(serial);
                self
            }
        }

        impl Enumerated for Dev {
            fn vid(&self) -> u16 {
                self.vid
            }
            fn pid(&self) -> u16 {
                self.pid
            }
            fn serial(&self) -> Option<&str> {
                self.serial
            }
            fn adb_interface(&self) -> Option<u8> {
                self.adb
            }
        }

        /// Scan that reports which device was picked, by pid.
        fn pick(
            devices: Vec<Dev>,
            selector: UsbSelector<'_>,
        ) -> Result<(u16, u8), UsbConnectError> {
            scan(devices, selector, |d, iface| Ok((d.pid, iface)))
        }

        #[test]
        fn a_transfer_error_stays_reachable_through_the_wrapper() {
            use core::error::Error as _;
            let err = UsbError(nusb::transfer::TransferError::Cancelled);
            let source = err.source().expect("the transfer error is the source");
            assert_eq!(
                alloc::format!("{source}"),
                alloc::format!("{}", nusb::transfer::TransferError::Cancelled)
            );
        }

        #[test]
        fn any_walks_past_a_device_without_an_adb_interface() {
            let devices = vec![
                Dev::new(0xf00d, 0x0001, None),
                Dev::new(0xf00d, 0x0002, None),
                Dev::new(0xbeef, 0x0001, Some(1)),
            ];
            assert_eq!(pick(devices, UsbSelector::Any).unwrap(), (0x0001, 1));
        }

        #[test]
        fn any_finds_nothing_when_no_device_speaks_adb() {
            let devices = vec![Dev::new(0xf00d, 0x0001, None)];
            assert!(matches!(
                pick(devices, UsbSelector::Any),
                Err(UsbConnectError::NotFound)
            ));
        }

        #[test]
        fn vid_pid_ignores_other_devices() {
            let devices = vec![
                Dev::new(0xf00d, 0x0001, Some(0)),
                Dev::new(0xbeef, 0x0001, Some(2)),
            ];
            let selector = UsbSelector::VidPid {
                vid: 0xbeef,
                pid: 0x0001,
            };
            assert_eq!(pick(devices, selector).unwrap(), (0x0001, 2));
        }

        #[test]
        fn a_vid_pid_has_to_match_both_halves() {
            let selector = UsbSelector::VidPid {
                vid: 0x18d1,
                pid: 0x4ee7,
            };
            let same_vid = vec![Dev::new(0x18d1, 0x4ee8, Some(0))];
            assert!(matches!(
                pick(same_vid, selector),
                Err(UsbConnectError::NotFound)
            ));
            let same_pid = vec![Dev::new(0x18d2, 0x4ee7, Some(0))];
            assert!(matches!(
                pick(same_pid, selector),
                Err(UsbConnectError::NotFound)
            ));
        }

        #[test]
        fn a_named_device_without_an_adb_interface_says_so() {
            let devices = vec![Dev::new(0xbeef, 0x0001, None)];
            let selector = UsbSelector::VidPid {
                vid: 0xbeef,
                pid: 0x0001,
            };
            assert!(matches!(
                pick(devices, selector),
                Err(UsbConnectError::NoAdbInterface)
            ));
        }

        #[test]
        fn a_serial_picks_its_own_device() {
            let devices = vec![
                Dev::new(0xbeef, 0x0001, Some(0)).with_serial("OTHER"),
                Dev::new(0xbeef, 0x0001, Some(1)).with_serial("WANTED"),
            ];
            assert_eq!(
                pick(devices, UsbSelector::Serial("WANTED")).unwrap(),
                (0x0001, 1)
            );
        }

        #[test]
        fn an_unclaimable_device_does_not_end_an_any_scan() {
            let devices = vec![
                Dev::new(0xbeef, 0x0001, Some(0)),
                Dev::new(0xbeef, 0x0002, Some(1)),
            ];
            let mut seen = 0;
            let picked = scan(devices, UsbSelector::Any, |d, iface| {
                seen += 1;
                if d.pid == 0x0001 {
                    Err(UsbConnectError::NoBulkEndpoints)
                } else {
                    Ok((d.pid, iface))
                }
            });
            assert_eq!(picked.unwrap(), (0x0002, 1));
            assert_eq!(seen, 2);
        }

        #[test]
        fn the_first_failure_is_reported_when_the_scan_finds_nothing_else() {
            let devices = vec![Dev::new(0xbeef, 0x0001, Some(0))];
            let picked: Result<(), _> = scan(devices, UsbSelector::Any, |_, _| {
                Err(UsbConnectError::NoBulkEndpoints)
            });
            assert!(matches!(picked, Err(UsbConnectError::NoBulkEndpoints)));
        }

        #[test]
        fn a_named_device_surfaces_its_failure_at_once() {
            let devices = vec![
                Dev::new(0xbeef, 0x0001, Some(0)),
                Dev::new(0xbeef, 0x0001, Some(1)),
            ];
            let selector = UsbSelector::VidPid {
                vid: 0xbeef,
                pid: 0x0001,
            };
            let mut seen = 0;
            let picked: Result<(), _> = scan(devices, selector, |_, _| {
                seen += 1;
                Err(UsbConnectError::NoBulkEndpoints)
            });
            assert!(matches!(picked, Err(UsbConnectError::NoBulkEndpoints)));
            assert_eq!(seen, 1);
        }
    }
}
