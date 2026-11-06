//! What the USB backends share: which enumerated device a
//! [`UsbSelector`] picks, what is reported when none will do, and which
//! bulk OUT transfers a zero-length packet has to end.

#[cfg(test)]
mod tests;

use alloc::string::String;

use crate::transport::uri::UsbSelector;
use crate::transport::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};

/// What device selection needs to know about one enumerated device,
/// so both backends and the tests' fake share the rules of [`scan`].
/// `scan` stops at the first lookup that rules a device out.
/// [`serial`](Self::serial) comes last, and only under
/// [`UsbSelector::Serial`], as libusb needs an open handle for it: it
/// may open the device, and the handle stays for `scan`'s `open` step.
pub(super) trait Enumerated {
    /// The backend's connect error, which a failed lookup reports.
    type Error: ScanError;

    /// What [`adb_interface`](Self::adb_interface) found and `scan`'s
    /// `open` step claims: the interface number, and whatever else the
    /// backend read alongside it that opening would otherwise read
    /// again.
    type Interface;

    /// USB vendor ID.
    fn vid(&self) -> u16;

    /// USB product ID.
    fn pid(&self) -> u16;

    /// The first interface that [speaks ADB](speaks_adb), or `None` if
    /// none does. A backend that can tell from the descriptors that an
    /// interface is unusable passes it over here, before anything is
    /// opened.
    fn adb_interface(&self) -> Result<Option<Self::Interface>, Self::Error>;

    /// The serial number, or `None` if the device reports none.
    fn serial(&mut self) -> Result<Option<String>, Self::Error>;
}

/// The two failures [`scan`] reports by itself, in terms of the
/// backend's own connect error.
pub(super) trait ScanError {
    /// No device matched the selector.
    fn not_found() -> Self;

    /// The device a VID:PID names has no ADB interface.
    fn no_adb_interface() -> Self;
}

/// Whether an interface of this class, subclass and protocol is an ADB
/// interface.
pub(super) fn speaks_adb(class: u8, subclass: u8, protocol: u8) -> bool {
    (class, subclass, protocol) == (ADB_CLASS, ADB_SUBCLASS, ADB_PROTOCOL)
}

/// Hand the first device the selector accepts to `open`, with its ADB
/// interface, and walk on if that one turns out unusable. A VID:PID
/// names one device, so its failures are reported as they happen. `Any`
/// and a serial are searches, which a hub ahead of the phone must not
/// end: a failing device is passed over, and the first failure reported
/// only if nothing works out, as every selector does with unreadable IDs.
pub(super) fn scan<D, T, F>(
    devices: impl IntoIterator<Item = Result<D, D::Error>>,
    selector: UsbSelector<'_>,
    mut open: F,
) -> Result<T, D::Error>
where
    D: Enumerated,
    F: FnMut(D, D::Interface) -> Result<T, D::Error>,
{
    let named = matches!(selector, UsbSelector::VidPid { .. });
    let mut first_err = None;

    for device in devices {
        let mut device = match device {
            Ok(device) => device,
            Err(e) => {
                first_err.get_or_insert(e);
                continue;
            }
        };
        let attempt = match admit(&mut device, selector) {
            Ok(Some(iface)) => open(device, iface),
            Ok(None) => continue,
            Err(e) => Err(e),
        };
        match attempt {
            Ok(transport) => return Ok(transport),
            Err(e) if named => return Err(e),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }

    Err(first_err.unwrap_or_else(D::Error::not_found))
}

/// The ADB interface `selector` wants `device` opened on, or `None` if
/// it passes the device over.
fn admit<D: Enumerated>(
    device: &mut D,
    selector: UsbSelector<'_>,
) -> Result<Option<D::Interface>, D::Error> {
    if let UsbSelector::VidPid { vid, pid } = selector {
        if (device.vid(), device.pid()) != (vid, pid) {
            return Ok(None);
        }
    }

    let Some(iface) = device.adb_interface()? else {
        return match selector {
            UsbSelector::VidPid { .. } => Err(D::Error::no_adb_interface()),
            _ => Ok(None),
        };
    };

    if let UsbSelector::Serial(wanted) = selector {
        if device.serial()?.as_deref() != Some(wanted) {
            return Ok(None);
        }
    }

    Ok(Some(iface))
}

/// Whether a bulk OUT of `len` bytes fills the last of its packets of
/// `max_packet` bytes, and so takes a zero-length packet to end.
///
/// A transfer ends at a short packet or when the request reading it is
/// full, and adbd reads in 16 KiB requests, so without an end of its
/// own a shorter transfer sits on the device until the next one comes
/// along. Length alone decides, a transfer of 16 KiB included: adbd
/// passes over the empty read that leaves it.
///
/// A descriptor reporting a packet size of 0 gives no boundary to end
/// on, and a `len` of 0 is no transfer to end.
pub(super) fn ends_on_packet_boundary(len: usize, max_packet: usize) -> bool {
    len != 0 && len.checked_rem(max_packet) == Some(0)
}
