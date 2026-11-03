//! Device selection shared by the USB backends: which enumerated device
//! a [`UsbSelector`] picks, and what is reported when none will do.

use alloc::string::String;

use crate::transport::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};
use crate::uri::UsbSelector;

/// What device selection needs to know about one enumerated device.
///
/// Each backend implements it for its own device type, so both pick a
/// device by the rules of [`scan`], and a fake device lets the tests
/// exercise those rules without a USB bus.
///
/// The lookups grow costlier down the list, and `scan` stops at the
/// first one that rules a device out. The IDs come with enumeration,
/// and a device whose IDs could not be read reaches `scan` as an `Err`
/// instead. The interfaces come from the configuration descriptor,
/// which libusb may fail to read. The serial number is a string
/// descriptor libusb can only read through an open handle, so
/// [`serial`](Self::serial) takes `&mut self`: it may open the device,
/// fail doing so, and keep the handle for `scan`'s `open` step. `scan`
/// asks for it last, and only under [`UsbSelector::Serial`], so no
/// other selector opens a device it will not use. A backend that has
/// the serial from enumeration, as `nusb` does, just hands it over.
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

/// Walk `devices`, handing the first one the selector accepts to
/// `open` along with its ADB interface, and keep walking if that one
/// turns out unusable.
///
/// A VID:PID names one device, so its failures are reported as they
/// happen. `Any` and a serial number describe a search: a device that
/// speaks no ADB, cannot be looked into, or refuses to open, is passed
/// over, and the first failure is only reported if nothing else works
/// out. Without that, a hub or a webcam enumerated ahead of the phone
/// ends the search.
///
/// A device whose IDs could not be read may be any device, the one a
/// VID:PID names included, so every selector passes it over and keeps
/// its failure. A VID:PID that then matches nothing reports that
/// failure rather than [`not_found`](ScanError::not_found).
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

#[cfg(test)]
mod tests;
