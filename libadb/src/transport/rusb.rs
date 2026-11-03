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
use crate::transport::usb::{scan, speaks_adb, Enumerated, ScanError};
use crate::uri::UsbSelector;

const NO_TIMEOUT: Duration = Duration::ZERO;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);

/// USB transport wrapping a `rusb::DeviceHandle` with bulk endpoints.
///
/// Cheap to clone — the handle is held behind `Arc` and the internal
/// staging buffer is reset to empty in the clone. Cloning shares the
/// same libusb handle and endpoints, which makes it safe to use one
/// clone for reading and another for writing concurrently (see
/// [`Splittable`](crate::Splittable)).
///
/// # Cancellation
///
/// Under the `tokio` / `smol` features the bulk transfers run on a
/// blocking worker thread (`spawn_blocking` / `unblock`) when a
/// runtime is present, and inline on the calling thread otherwise
/// (e.g. under the blocking `libadb-ffi` executor). Dropping
/// the returned future does **not** cancel the in-flight USB
/// transfer — libusb has no async cancel — so a partial bulk write
/// may still complete on the device. Subsequent calls on the same
/// transport may then observe wire-framing corruption. Avoid
/// cancelling read/write futures; use the connection-level
/// timeout/error paths to terminate transfers cleanly. A cancelled
/// write marks the connection desynchronized
/// ([`Error::Desynchronized`](crate::Error::Desynchronized)), and
/// reads report themselves as unsafe to cancel through
/// [`ReadCancelSafety`](crate::transport::ReadCancelSafety), so
/// [`select_channel`](crate::Connection::select_channel) checks its
/// interrupt between reads rather than racing it against one.
pub struct UsbTransport<R> {
    handle: Arc<rusb::DeviceHandle<Context>>,
    ep_in: u8,
    ep_out: u8,
    runtime: core::marker::PhantomData<R>,
    // Reused across read/write to avoid per-call heap allocation
    // when crossing the spawn_blocking/unblock boundary under the
    // tokio/smol runtime variants. Empty under the no-runtime path
    // since that one reads/writes directly into the caller buffer.
    #[cfg_attr(not(any(feature = "tokio", feature = "smol")), allow(dead_code))]
    buffer: Vec<u8>,
}

impl<R> Clone for UsbTransport<R> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            ep_in: self.ep_in,
            ep_out: self.ep_out,
            runtime: core::marker::PhantomData,
            buffer: Vec::new(),
        }
    }
}

impl<R: Runtime> UsbTransport<R> {
    /// Build a transport from an already-claimed `rusb::DeviceHandle`,
    /// picking bulk IN/OUT endpoints from the given interface.
    pub fn new(handle: rusb::DeviceHandle<Context>, iface: u8) -> Result<Self, UsbConnectError> {
        let config = handle
            .device()
            .active_config_descriptor()
            .map_err(UsbConnectError::Descriptor)?;
        let (ep_in, ep_out) = config
            .interfaces()
            .filter(|i| i.number() == iface)
            .flat_map(|i| i.descriptors())
            .find_map(|desc| bulk_endpoints(&desc))
            .ok_or(UsbConnectError::NoBulkEndpoints)?;
        Ok(Self::from_parts(handle, ep_in, ep_out))
    }

    fn from_parts(handle: rusb::DeviceHandle<Context>, ep_in: u8, ep_out: u8) -> Self {
        Self {
            handle: Arc::new(handle),
            ep_in,
            ep_out,
            runtime: core::marker::PhantomData,
            buffer: Vec::new(),
        }
    }

    /// Read from the bulk IN endpoint, on `R`'s blocking pool.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, UsbError> {
        let handle = self.handle.clone();
        let ep = self.ep_in;
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

    /// Write to the bulk OUT endpoint, on `R`'s blocking pool.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, UsbError> {
        let handle = self.handle.clone();
        let ep = self.ep_out;
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.clear();
        buffer.extend_from_slice(buf);
        let (n, buffer) = R::run_blocking(move || {
            let n = bulk_write(&handle, ep, &buffer)?;
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

fn bulk_write(handle: &rusb::DeviceHandle<Context>, ep: u8, buf: &[u8]) -> Result<usize, UsbError> {
    if buf.is_empty() {
        return Ok(0);
    }
    handle
        .write_bulk(ep, buf, NO_TIMEOUT)
        .map_err(UsbError::Transfer)
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
        embedded_io::ErrorKind::Other
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
    /// Reading a configuration descriptor failed.
    Descriptor(rusb::Error),
    /// Reading the serial-number string descriptor failed during a
    /// [`UsbSelector::Serial`] probe.
    SerialRead(rusb::Error),
    /// Claiming the interface failed.
    Claim(rusb::Error),
    /// The claimed interface has no bulk IN/OUT endpoints.
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
    // libusb has kept the device descriptor in memory since 1.0.16 and
    // no longer fails to hand it out.
    let candidates = devices.iter().filter_map(|device| {
        let descriptor = device.device_descriptor().ok()?;
        Some(Candidate {
            device,
            descriptor,
            handle: None,
        })
    });
    scan(candidates, selector, |candidate, iface| {
        let handle = candidate.open()?;
        handle
            .claim_interface(iface)
            .map_err(UsbConnectError::Claim)?;
        UsbTransport::new(handle, iface)
    })
}

/// One enumerated device, opened only once the scan needs a handle.
struct Candidate {
    device: rusb::Device<Context>,
    descriptor: rusb::DeviceDescriptor,
    handle: Option<rusb::DeviceHandle<Context>>,
}

impl Candidate {
    /// The handle reading the serial opened, or a fresh one.
    fn open(self) -> Result<rusb::DeviceHandle<Context>, UsbConnectError> {
        match self.handle {
            Some(handle) => Ok(handle),
            None => self.device.open().map_err(UsbConnectError::Open),
        }
    }
}

impl Enumerated for Candidate {
    type Error = UsbConnectError;

    fn vid(&self) -> u16 {
        self.descriptor.vendor_id()
    }

    fn pid(&self) -> u16 {
        self.descriptor.product_id()
    }

    fn adb_interface(&self) -> Result<Option<u8>, UsbConnectError> {
        let config = self
            .device
            .active_config_descriptor()
            .map_err(UsbConnectError::Descriptor)?;
        Ok(config
            .interfaces()
            .flat_map(|i| i.descriptors())
            .find(|desc| {
                speaks_adb(
                    desc.class_code(),
                    desc.sub_class_code(),
                    desc.protocol_code(),
                )
            })
            .map(|desc| desc.interface_number()))
    }

    fn serial(&mut self) -> Result<Option<String>, UsbConnectError> {
        // The device descriptor says whether there is a string to read,
        // so a device without one is not opened to find out.
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

/// The bulk IN and OUT endpoint addresses of one interface setting.
fn bulk_endpoints(desc: &rusb::InterfaceDescriptor<'_>) -> Option<(u8, u8)> {
    let mut ep_in = None;
    let mut ep_out = None;
    for ep in desc.endpoint_descriptors() {
        if ep.transfer_type() == TransferType::Bulk {
            match ep.direction() {
                Direction::In => ep_in = Some(ep.address()),
                Direction::Out => ep_out = Some(ep.address()),
            }
        }
    }
    Some((ep_in?, ep_out?))
}

#[cfg(all(test, feature = "rusb"))]
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
