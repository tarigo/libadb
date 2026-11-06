//! ADB over USB transport (libusb / `rusb` backend).
//!
//! Functional counterpart of `crate::transport::nusb` but built on the
//! blocking `rusb`/libusb bindings. Both features may be enabled at
//! once; the `Rusb` marker selects this backend at a call site.
//!
//! Bulk transfers block the thread they run on — a runtime pool
//! thread, or the caller itself under the `Inline` runtime and under
//! `Tokio` when no Tokio runtime is active (its `run_blocking` then
//! deliberately runs inline) — with no timeout: a read returns when
//! the device answers or detaches, and cannot be cancelled from the
//! host side. Slicing the wait into timeouts is not an option (`rusb`
//! discards the bytes a transfer had already received when it reports
//! `Timeout`), and `nusb` is no escape hatch for cancellation either —
//! aborting an in-flight read forfeits the connection on both
//! backends, see
//! [`ReadCancelSafety`](crate::transport::ReadCancelSafety). What
//! `nusb` buys is waiting without parking an OS thread.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use rusb::{Context, Direction, TransferType, UsbContext};

use crate::transport::runtime::Runtime;
use crate::transport::uri::UsbSelector;
use crate::transport::usb::{ends_on_packet_boundary, scan, speaks_adb, Enumerated, ScanError};

const NO_TIMEOUT: Duration = Duration::ZERO;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);

const PACKET_SIZE_MASK: u16 = 0x07ff;

/// USB transport wrapping a `rusb::DeviceHandle` with bulk endpoints.
///
/// Cheap to clone: the handle is held behind `Arc`, and the internal
/// staging buffer is reset to empty in the clone. One clone can read
/// while another writes (see [`Splittable`](crate::Splittable)).
///
/// [`write`](Self::write) follows a transfer that fills its last USB
/// packet with a zero-length one. adbd reads in 16 KiB requests, and
/// only a short packet completes one early, so the bytes would
/// otherwise sit on the device until the next write.
///
/// # Cancellation
///
/// Dropping a read or write future does **not** cancel the in-flight
/// USB transfer: libusb has no async cancel, so a partial bulk write
/// may still complete on the device, and later calls on the same
/// transport may then observe wire-framing corruption. Avoid
/// cancelling read/write futures; use the connection-level
/// timeout/error paths to terminate transfers cleanly. See also
/// [`Error::Desynchronized`](crate::Error::Desynchronized) and
/// [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
pub struct UsbTransport<R> {
    handle: Arc<rusb::DeviceHandle<Context>>,
    endpoints: BulkEndpoints,
    runtime: core::marker::PhantomData<R>,
    buffer: Vec<u8>,
}

impl<R> Clone for UsbTransport<R> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            endpoints: self.endpoints,
            runtime: core::marker::PhantomData,
            buffer: Vec::new(),
        }
    }
}

impl<R: Runtime> UsbTransport<R> {
    /// Build a transport from an already-claimed `rusb::DeviceHandle`,
    /// picking bulk IN/OUT endpoints from the given interface, and how
    /// large a packet the OUT one takes.
    pub fn new(handle: rusb::DeviceHandle<Context>, iface: u8) -> Result<Self, UsbConnectError> {
        let config = handle
            .device()
            .active_config_descriptor()
            .map_err(UsbConnectError::Descriptor)?;
        let endpoints = config
            .interfaces()
            .filter(|i| i.number() == iface)
            .flat_map(|i| i.descriptors())
            .find_map(|desc| bulk_endpoints(&desc))
            .ok_or(UsbConnectError::NoBulkEndpoints)?;
        Ok(Self::from_parts(handle, endpoints))
    }

    fn from_parts(handle: rusb::DeviceHandle<Context>, endpoints: BulkEndpoints) -> Self {
        Self {
            handle: Arc::new(handle),
            endpoints,
            runtime: core::marker::PhantomData,
            buffer: Vec::new(),
        }
    }

    /// Read from the bulk IN endpoint, on `R`'s blocking pool.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, UsbError> {
        let handle = self.handle.clone();
        let ep = self.endpoints.ep_in;
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.resize(buf.len(), 0);
        let (n, buffer) = R::run_blocking(move || {
            let n = bulk_read(&handle, ep, &mut buffer)?;
            Ok::<_, UsbError>((n, buffer))
        })
        .await
        .map_err(|_| UsbError::BlockingTaskFailed)??;
        buf[..n].copy_from_slice(&buffer[..n]);
        self.buffer = buffer;
        Ok(n)
    }

    /// Write to the bulk OUT endpoint, on `R`'s blocking pool, as one
    /// transfer and, if that fills its last packet, a zero-length one
    /// to end it. An empty `buf` sends nothing.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, UsbError> {
        let handle = self.handle.clone();
        let endpoints = self.endpoints;
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.clear();
        buffer.extend_from_slice(buf);
        let (n, buffer) = R::run_blocking(move || {
            let n = bulk_write(&handle, endpoints, &buffer)?;
            Ok::<_, UsbError>((n, buffer))
        })
        .await
        .map_err(|_| UsbError::BlockingTaskFailed)??;
        self.buffer = buffer;
        Ok(n)
    }
}

fn bulk_read(
    handle: &rusb::DeviceHandle<Context>,
    ep: u8,
    buf: &mut [u8],
) -> Result<usize, UsbError> {
    if buf.is_empty() {
        return Ok(0);
    }
    handle
        .read_bulk(ep, buf, NO_TIMEOUT)
        .map_err(UsbError::Transfer)
}

fn bulk_write(
    handle: &rusb::DeviceHandle<Context>,
    endpoints: BulkEndpoints,
    buf: &[u8],
) -> Result<usize, UsbError> {
    if buf.is_empty() {
        return Ok(0);
    }
    let ep = endpoints.ep_out;
    let n = handle
        .write_bulk(ep, buf, NO_TIMEOUT)
        .map_err(UsbError::Transfer)?;
    if n == buf.len() && ends_on_packet_boundary(n, endpoints.out_packet_size) {
        handle
            .write_bulk(ep, &[], NO_TIMEOUT)
            .map_err(UsbError::Transfer)?;
    }
    Ok(n)
}

impl<R> embedded_io::ErrorType for UsbTransport<R> {
    type Error = UsbError;
}

impl<R: Runtime> embedded_io_async::Read for UsbTransport<R> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        UsbTransport::read(self, buf).await
    }
}

impl<R: Runtime> embedded_io_async::Write for UsbTransport<R> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        UsbTransport::write(self, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Dropping a bulk transfer discards whatever the device already
// put in it: those bytes are gone, not waiting to be re-read.
impl<R> crate::transport::ReadCancelSafety for UsbTransport<R> {
    fn read_cancel_safe(&self) -> bool {
        false
    }
}

impl<R: Runtime> crate::transport::Splittable for UsbTransport<R> {
    type ReadHalf = UsbTransport<R>;
    type WriteHalf = UsbTransport<R>;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), UsbError> {
        let clone = self.clone();
        Ok((self, clone))
    }
}

/// Errors from the rusb-backed USB transport.
#[derive(Debug)]
#[non_exhaustive]
pub enum UsbError {
    /// A libusb transfer or descriptor call failed.
    Transfer(rusb::Error),
    /// The runtime's blocking-task pool failed to deliver a result —
    /// typically the task was cancelled or panicked during runtime
    /// shutdown.
    BlockingTaskFailed,
}

impl core::fmt::Display for UsbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transfer(e) => write!(f, "usb: {e}"),
            Self::BlockingTaskFailed => f.write_str("usb: blocking task failed"),
        }
    }
}

impl core::error::Error for UsbError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transfer(e) => Some(e),
            Self::BlockingTaskFailed => None,
        }
    }
}

impl embedded_io::Error for UsbError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Transfer(rusb::Error::NoDevice) => embedded_io::ErrorKind::NotConnected,
            Self::Transfer(_) | Self::BlockingTaskFailed => embedded_io::ErrorKind::Other,
        }
    }
}

/// Reasons USB connect can fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum UsbConnectError {
    /// Initialising a libusb context failed.
    Context(rusb::Error),
    /// Device enumeration failed.
    Enumerate(rusb::Error),
    /// No device matched the selector.
    NotFound,
    /// Matching device has no ADB-class interface.
    NoAdbInterface,
    /// Opening the device failed.
    Open(rusb::Error),
    /// Reading a device or configuration descriptor failed.
    Descriptor(rusb::Error),
    /// Reading the serial-number string descriptor failed during a
    /// [`UsbSelector::Serial`] probe.
    SerialRead(rusb::Error),
    /// Claiming the interface failed.
    Claim(rusb::Error),
    /// The ADB interface has no bulk IN/OUT endpoints.
    NoBulkEndpoints,
}

impl core::fmt::Display for UsbConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Context(e) => write!(f, "libusb init: {e}"),
            Self::Enumerate(e) => write!(f, "enumerate: {e}"),
            Self::NotFound => f.write_str("device not found"),
            Self::NoAdbInterface => f.write_str("no adb interface on device"),
            Self::Open(e) => write!(f, "open: {e}"),
            Self::Descriptor(e) => write!(f, "descriptor: {e}"),
            Self::SerialRead(e) => write!(f, "serial read: {e}"),
            Self::Claim(e) => write!(f, "claim: {e}"),
            Self::NoBulkEndpoints => f.write_str("interface has no bulk endpoints"),
        }
    }
}

impl core::error::Error for UsbConnectError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Context(e)
            | Self::Enumerate(e)
            | Self::Open(e)
            | Self::Descriptor(e)
            | Self::SerialRead(e)
            | Self::Claim(e) => Some(e),
            Self::NotFound | Self::NoAdbInterface | Self::NoBulkEndpoints => None,
        }
    }
}

/// The `rusb` backend: libusb, blocking bulk transfers.
///
/// Zero-sized marker for [`UsbBackend`](crate::transport::UsbBackend);
/// pass it where a backend is required, e.g.
/// `any::connect::<Tokio, Rusb>("usb://")`.
pub struct Rusb;

impl<R: Runtime> crate::transport::UsbBackend<R> for Rusb {
    type Transport = UsbTransport<R>;
    type Error = UsbConnectError;

    fn connect_by_selector(selector: UsbSelector<'_>) -> Result<UsbTransport<R>, UsbConnectError> {
        connect_by_selector(selector)
    }
}

/// Enumerate USB devices, pick one matching `selector`, claim its
/// ADB interface, and build a [`UsbTransport`].
///
/// Synchronous: libusb enumerate/open/claim are blocking calls.
pub fn connect_by_selector<R: Runtime>(
    selector: UsbSelector<'_>,
) -> Result<UsbTransport<R>, UsbConnectError> {
    let context = Context::new().map_err(UsbConnectError::Context)?;
    let devices = context.devices().map_err(UsbConnectError::Enumerate)?;
    let candidates = devices.iter().map(|device| {
        let descriptor = device
            .device_descriptor()
            .map_err(UsbConnectError::Descriptor)?;
        Ok(Candidate {
            device,
            descriptor,
            handle: None,
        })
    });
    scan(candidates, selector, |candidate, iface| {
        let handle = candidate.open()?;
        handle
            .claim_interface(iface.number)
            .map_err(UsbConnectError::Claim)?;
        Ok(UsbTransport::from_parts(handle, iface.endpoints))
    })
}

struct Candidate {
    device: rusb::Device<Context>,
    descriptor: rusb::DeviceDescriptor,
    handle: Option<rusb::DeviceHandle<Context>>,
}

impl Candidate {
    fn open(self) -> Result<rusb::DeviceHandle<Context>, UsbConnectError> {
        match self.handle {
            Some(handle) => Ok(handle),
            None => self.device.open().map_err(UsbConnectError::Open),
        }
    }
}

impl Enumerated for Candidate {
    type Error = UsbConnectError;
    type Interface = AdbInterface;

    fn vid(&self) -> u16 {
        self.descriptor.vendor_id()
    }

    fn pid(&self) -> u16 {
        self.descriptor.product_id()
    }

    fn adb_interface(&self) -> Result<Option<AdbInterface>, UsbConnectError> {
        let config = self
            .device
            .active_config_descriptor()
            .map_err(UsbConnectError::Descriptor)?;
        first_with_bulk_endpoints(
            config
                .interfaces()
                .flat_map(|i| i.descriptors())
                .filter(|desc| {
                    speaks_adb(
                        desc.class_code(),
                        desc.sub_class_code(),
                        desc.protocol_code(),
                    )
                })
                .map(|desc| (desc.interface_number(), bulk_endpoints(&desc))),
        )
    }

    fn serial(&mut self) -> Result<Option<String>, UsbConnectError> {
        if self.descriptor.serial_number_string_index().is_none() {
            return Ok(None);
        }
        let handle = match self.handle.take() {
            Some(handle) => handle,
            None => self.device.open().map_err(UsbConnectError::Open)?,
        };
        let handle = self.handle.insert(handle);
        let langs = handle
            .read_languages(CONTROL_TIMEOUT)
            .map_err(UsbConnectError::SerialRead)?;
        let Some(&lang) = langs.first() else {
            return Ok(None);
        };
        handle
            .read_serial_number_string(lang, &self.descriptor, CONTROL_TIMEOUT)
            .map(Some)
            .map_err(UsbConnectError::SerialRead)
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

struct AdbInterface {
    number: u8,
    endpoints: BulkEndpoints,
}

#[derive(Clone, Copy)]
struct BulkEndpoints {
    ep_in: u8,
    ep_out: u8,
    out_packet_size: usize,
}

fn first_with_bulk_endpoints(
    settings: impl IntoIterator<Item = (u8, Option<BulkEndpoints>)>,
) -> Result<Option<AdbInterface>, UsbConnectError> {
    let mut settings = settings.into_iter().peekable();
    if settings.peek().is_none() {
        return Ok(None);
    }
    settings
        .find_map(|(number, endpoints)| {
            Some(AdbInterface {
                number,
                endpoints: endpoints?,
            })
        })
        .map(Some)
        .ok_or(UsbConnectError::NoBulkEndpoints)
}

fn bulk_endpoints(desc: &rusb::InterfaceDescriptor<'_>) -> Option<BulkEndpoints> {
    pick_bulk_endpoints(desc.endpoint_descriptors().map(|ep| {
        (
            ep.transfer_type(),
            ep.direction(),
            ep.address(),
            ep.max_packet_size(),
        )
    }))
}

fn pick_bulk_endpoints(
    endpoints: impl IntoIterator<Item = (TransferType, Direction, u8, u16)>,
) -> Option<BulkEndpoints> {
    let mut ep_in = None;
    let mut ep_out = None;
    for (transfer_type, direction, address, max_packet_size) in endpoints {
        if transfer_type == TransferType::Bulk {
            match direction {
                Direction::In => ep_in = Some(address),
                Direction::Out => ep_out = Some((address, max_packet_size)),
            }
        }
    }
    let (ep_out, max_packet_size) = ep_out?;
    Some(BulkEndpoints {
        ep_in: ep_in?,
        ep_out,
        out_packet_size: usize::from(max_packet_size & PACKET_SIZE_MASK),
    })
}

#[cfg(test)]
mod tests {
    use crate::transport::runtime::Inline;
    use crate::transport::rusb::Rusb;
    use crate::transport::UsbBackend;

    #[test]
    fn a_connect_error_leads_to_the_libusb_error_behind_it() {
        use crate::transport::rusb::UsbConnectError;
        use core::error::Error as _;
        let err = UsbConnectError::Claim(rusb::Error::Busy);
        let source = err.source().expect("the libusb error is the source");
        assert_eq!(
            alloc::format!("{source}"),
            alloc::format!("{}", rusb::Error::Busy)
        );
        assert!(UsbConnectError::NotFound.source().is_none());
    }

    #[test]
    fn a_transfer_error_stays_reachable_through_the_wrapper() {
        use crate::transport::rusb::UsbError;
        use core::error::Error as _;
        let err = UsbError::Transfer(rusb::Error::Pipe);
        let source = err.source().expect("the transfer error is the source");
        assert_eq!(
            alloc::format!("{source}"),
            alloc::format!("{}", rusb::Error::Pipe)
        );
        assert!(UsbError::BlockingTaskFailed.source().is_none());
    }

    /// What the connection goes by to tell a device gone from any other
    /// failed transfer.
    #[test]
    fn a_device_gone_is_not_connected() {
        use crate::transport::rusb::UsbError;
        use embedded_io::{Error as _, ErrorKind};

        let kind = |e| UsbError::Transfer(e).kind();
        assert_eq!(kind(rusb::Error::NoDevice), ErrorKind::NotConnected);
        for other in [rusb::Error::Io, rusb::Error::Pipe, rusb::Error::Timeout] {
            assert_eq!(kind(other), ErrorKind::Other, "{other:?}");
        }
        assert_eq!(UsbError::BlockingTaskFailed.kind(), ErrorKind::Other);
    }

    /// An ADB setting without both bulk endpoints is passed over, and a
    /// device with no other is turned down for that, not for speaking no
    /// ADB: the scan rejects it before opening it.
    #[test]
    fn the_adb_interface_is_the_first_with_both_bulk_endpoints() {
        use crate::transport::rusb::{first_with_bulk_endpoints, BulkEndpoints, UsbConnectError};
        let endpoints = |ep_in, ep_out| {
            Some(BulkEndpoints {
                ep_in,
                ep_out,
                out_packet_size: 512,
            })
        };
        let found = first_with_bulk_endpoints([
            (0, None),
            (1, endpoints(0x81, 0x01)),
            (2, endpoints(0x82, 0x02)),
        ]);
        let iface = found.expect("the descriptor was read").expect("found");
        let BulkEndpoints { ep_in, ep_out, .. } = iface.endpoints;
        assert_eq!((iface.number, ep_in, ep_out), (1, 0x81, 0x01));
        assert!(matches!(
            first_with_bulk_endpoints([(0, None)]),
            Err(UsbConnectError::NoBulkEndpoints)
        ));
        assert!(matches!(first_with_bulk_endpoints([]), Ok(None)));
    }

    /// A write goes by the packet size of the OUT endpoint, wherever the
    /// descriptor lists it and whatever the other endpoints take, and of
    /// `wMaxPacketSize` it keeps nothing but the size.
    #[test]
    fn the_adb_interface_keeps_the_packet_size_of_its_out_endpoint() {
        use crate::transport::rusb::{first_with_bulk_endpoints, pick_bulk_endpoints};
        use rusb::{Direction, TransferType};
        let bulk_in = (TransferType::Bulk, Direction::In, 0x81, 1024);
        let bulk_out = (TransferType::Bulk, Direction::Out, 0x01, 512);
        let interrupt_out = (TransferType::Interrupt, Direction::Out, 0x02, 64);
        let flagged_out = (TransferType::Bulk, Direction::Out, 0x01, 0x1000 | 512);

        for endpoints in [
            alloc::vec![bulk_out, bulk_in],
            alloc::vec![bulk_in, interrupt_out, bulk_out],
            alloc::vec![bulk_out, interrupt_out, bulk_in],
            alloc::vec![bulk_in, flagged_out],
        ] {
            let iface = first_with_bulk_endpoints([(0, pick_bulk_endpoints(endpoints))])
                .expect("the descriptor was read")
                .expect("found");
            assert_eq!(iface.endpoints.out_packet_size, 512);
        }
        assert!(pick_bulk_endpoints([bulk_in, interrupt_out]).is_none());
    }

    #[test]
    fn the_backend_serves_every_runtime() {
        // Compiling this is the assertion: one marker, and the
        // transport it yields follows whichever runtime is asked for.
        fn takes_backend<R, B: UsbBackend<R>>() {}
        takes_backend::<Inline, Rusb>();

        #[cfg(feature = "tokio")]
        takes_backend::<crate::transport::runtime::Tokio, Rusb>();
        #[cfg(feature = "smol")]
        takes_backend::<crate::transport::runtime::Smol, Rusb>();
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn transports_of_different_runtimes_are_different_types() {
        use crate::transport::rusb::UsbTransport;
        use core::any::TypeId;

        // Would pass on trait conformance alone even if the runtime
        // parameter were erased, so compare the types themselves.
        assert_ne!(
            TypeId::of::<UsbTransport<Inline>>(),
            TypeId::of::<UsbTransport<crate::transport::runtime::Tokio>>(),
        );
    }
}
