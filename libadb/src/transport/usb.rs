#[cfg(test)]
mod tests;

use alloc::string::String;

use crate::transport::uri::UsbSelector;
use crate::transport::{ADB_CLASS, ADB_PROTOCOL, ADB_SUBCLASS};

pub(super) trait Enumerated {
    type Error: ScanError;

    type Interface;

    fn vid(&self) -> u16;

    fn pid(&self) -> u16;

    fn adb_interface(&self) -> Result<Option<Self::Interface>, Self::Error>;

    fn serial(&mut self) -> Result<Option<String>, Self::Error>;
}

pub(super) trait ScanError {
    fn not_found() -> Self;

    fn no_adb_interface() -> Self;
}

pub(super) fn speaks_adb(class: u8, subclass: u8, protocol: u8) -> bool {
    (class, subclass, protocol) == (ADB_CLASS, ADB_SUBCLASS, ADB_PROTOCOL)
}

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

pub(super) fn ends_on_packet_boundary(len: usize, max_packet: usize) -> bool {
    len != 0 && len.checked_rem(max_packet) == Some(0)
}
