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

#[cfg(feature = "rusb")]
pub use self::inner::*;

#[cfg(feature = "rusb")]
mod inner {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::time::Duration;
    use rusb::{Context, Direction, TransferType, UsbContext};

    use crate::transport::runtime::Runtime;
    use crate::transport::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};
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
        pub fn new(
            handle: rusb::DeviceHandle<Context>,
            iface: u8,
        ) -> Result<Self, UsbConnectError> {
            let (_, ep_in, ep_out) = find_interface_endpoints(&handle.device(), |desc| {
                desc.interface_number() == iface
            })?
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

    fn bulk_write(
        handle: &rusb::DeviceHandle<Context>,
        ep: u8,
        buf: &[u8],
    ) -> Result<usize, UsbError> {
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
        /// Reading a device or config descriptor failed.
        Descriptor(rusb::Error),
        /// Reading the serial-number string descriptor failed during a
        /// [`UsbSelector::Serial`](crate::uri::UsbSelector::Serial) probe.
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

    /// The `rusb` backend: libusb, blocking bulk transfers.
    ///
    /// Zero-sized marker for [`UsbBackend`](crate::transport::UsbBackend);
    /// pass it where a backend is required, e.g.
    /// `any::connect::<Tokio, Rusb>("usb://")`.
    pub struct Rusb;

    impl<R: Runtime> crate::transport::UsbBackend<R> for Rusb {
        type Transport = UsbTransport<R>;
        type Error = UsbConnectError;

        fn connect_by_selector(
            selector: UsbSelector<'_>,
        ) -> Result<UsbTransport<R>, UsbConnectError> {
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

        // VidPid pre-identifies a unique device, so per-device failures
        // are surfaced; Any/Serial keep scanning on failure but remember
        // the first probe error so it can be reported if no device
        // ultimately succeeds.
        let hard_fail = matches!(selector, UsbSelector::VidPid { .. });
        let mut first_err: Option<UsbConnectError> = None;

        for device in devices.iter() {
            match try_open_device(device, selector, hard_fail) {
                Ok(Some(t)) => return Ok(t),
                Ok(None) => continue,
                Err(e) if hard_fail => return Err(e),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }

        Err(first_err.unwrap_or(UsbConnectError::NotFound))
    }

    fn try_open_device<R: Runtime>(
        device: rusb::Device<Context>,
        selector: UsbSelector<'_>,
        hard_fail: bool,
    ) -> Result<Option<UsbTransport<R>>, UsbConnectError> {
        let desc = device
            .device_descriptor()
            .map_err(UsbConnectError::Descriptor)?;

        if let UsbSelector::VidPid { vid, pid } = selector {
            if desc.vendor_id() != vid || desc.product_id() != pid {
                return Ok(None);
            }
        }

        let (iface_num, ep_in, ep_out) = match find_interface_endpoints(&device, |desc| {
            desc.class_code() == ADB_CLASS
                && desc.sub_class_code() == ADB_SUBCLASS
                && desc.protocol_code() == ADB_PROTOCOL
        })? {
            Some(t) => t,
            None if hard_fail => return Err(UsbConnectError::NoAdbInterface),
            None => return Ok(None),
        };

        let handle = device.open().map_err(UsbConnectError::Open)?;

        // libusb reads the serial string through an open handle, so
        // Serial matching is deferred until after `open()` (nusb has
        // it as enumeration metadata and can match up front).
        if let UsbSelector::Serial(wanted) = selector {
            let serial = read_serial(&handle, &desc).map_err(UsbConnectError::SerialRead)?;
            if serial.as_deref() != Some(wanted) {
                return Ok(None);
            }
        }

        handle
            .claim_interface(iface_num)
            .map_err(UsbConnectError::Claim)?;
        Ok(Some(UsbTransport::from_parts(handle, ep_in, ep_out)))
    }

    fn find_interface_endpoints(
        device: &rusb::Device<Context>,
        pick: impl Fn(&rusb::InterfaceDescriptor) -> bool,
    ) -> Result<Option<(u8, u8, u8)>, UsbConnectError> {
        let config = device
            .active_config_descriptor()
            .map_err(UsbConnectError::Descriptor)?;
        let mut any_match = false;
        for iface in config.interfaces() {
            for desc in iface.descriptors() {
                if !pick(&desc) {
                    continue;
                }
                any_match = true;
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
                if let (Some(r), Some(w)) = (ep_in, ep_out) {
                    return Ok(Some((iface.number(), r, w)));
                }
            }
        }
        if any_match {
            Err(UsbConnectError::NoBulkEndpoints)
        } else {
            Ok(None)
        }
    }

    fn read_serial(
        handle: &rusb::DeviceHandle<Context>,
        desc: &rusb::DeviceDescriptor,
    ) -> Result<Option<alloc::string::String>, rusb::Error> {
        let langs = handle.read_languages(CONTROL_TIMEOUT)?;
        let Some(&lang) = langs.first() else {
            return Ok(None);
        };
        handle
            .read_serial_number_string(lang, desc, CONTROL_TIMEOUT)
            .map(Some)
    }
}

#[cfg(all(test, feature = "rusb"))]
mod tests {
    use crate::transport::runtime::Inline;
    use crate::transport::rusb::Rusb;
    use crate::transport::UsbBackend;

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
