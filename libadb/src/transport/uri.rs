//! URI parser for ADB transport addresses.
//!
//! Supported schemes:
//!
//! * `tcp://HOST:PORT` — `HOST` may be IPv4, a hostname, or a bracketed
//!   IPv6 address (`tcp://[::1]:5555`). Bare (unbracketed) IPv6 is
//!   rejected to keep the grammar unambiguous.
//! * `usb://` — any ADB-capable USB device.
//! * `usb://VID:PID` — USB device matching VID and PID as 4 hex digits
//!   each (case-insensitive).
//! * `usb://serial/SERIAL` — USB device with the given serial number.
//!
//! The parser is zero-copy: the returned [`Uri`] borrows slices of the
//! input string.

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uri<'a> {
    Tcp { host: &'a str, port: u16 },
    Usb(UsbSelector<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSelector<'a> {
    /// First available ADB device.
    Any,
    /// Match by USB vendor/product IDs.
    VidPid { vid: u16, pid: u16 },
    /// Match by serial number string.
    Serial(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UriError {
    /// No `scheme://` prefix.
    MissingScheme,
    /// Scheme is neither `tcp` nor `usb`.
    UnknownScheme,
    /// Host is empty, malformed, or contains a colon without brackets.
    InvalidHost,
    /// Port is missing, non-numeric, or out of range.
    InvalidPort,
    /// VID/PID is not 4 hex digits or the serial is empty.
    InvalidUsbSelector,
}

impl core::fmt::Display for UriError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingScheme => f.write_str("missing scheme"),
            Self::UnknownScheme => f.write_str("unknown scheme (expected tcp or usb)"),
            Self::InvalidHost => f.write_str("invalid host"),
            Self::InvalidPort => f.write_str("invalid port"),
            Self::InvalidUsbSelector => f.write_str("invalid usb selector"),
        }
    }
}

impl core::error::Error for UriError {}

/// Parse a transport URI.
pub fn parse(s: &str) -> Result<Uri<'_>, UriError> {
    let (scheme, rest) = s.split_once("://").ok_or(UriError::MissingScheme)?;
    match scheme {
        "tcp" => parse_tcp(rest),
        "usb" => parse_usb(rest),
        _ => Err(UriError::UnknownScheme),
    }
}

fn parse_tcp(rest: &str) -> Result<Uri<'_>, UriError> {
    if rest.is_empty() {
        return Err(UriError::InvalidHost);
    }
    if let Some(after_bracket) = rest.strip_prefix('[') {
        let (host, after) = after_bracket.split_once(']').ok_or(UriError::InvalidHost)?;
        if host.is_empty() {
            return Err(UriError::InvalidHost);
        }
        let port_str = after.strip_prefix(':').ok_or(UriError::InvalidPort)?;
        let port = port_str.parse::<u16>().map_err(|_| UriError::InvalidPort)?;
        Ok(Uri::Tcp { host, port })
    } else {
        let (host, port_str) = rest.rsplit_once(':').ok_or(UriError::InvalidPort)?;
        if host.is_empty() {
            return Err(UriError::InvalidHost);
        }
        if host.contains(':') {
            return Err(UriError::InvalidHost);
        }
        let port = port_str.parse::<u16>().map_err(|_| UriError::InvalidPort)?;
        Ok(Uri::Tcp { host, port })
    }
}

fn parse_usb(rest: &str) -> Result<Uri<'_>, UriError> {
    if rest.is_empty() {
        return Ok(Uri::Usb(UsbSelector::Any));
    }
    if let Some(serial) = rest.strip_prefix("serial/") {
        if serial.is_empty() {
            return Err(UriError::InvalidUsbSelector);
        }
        return Ok(Uri::Usb(UsbSelector::Serial(serial)));
    }
    let (vid_s, pid_s) = rest.split_once(':').ok_or(UriError::InvalidUsbSelector)?;
    if vid_s.len() != 4 || pid_s.len() != 4 {
        return Err(UriError::InvalidUsbSelector);
    }
    let vid = u16::from_str_radix(vid_s, 16).map_err(|_| UriError::InvalidUsbSelector)?;
    let pid = u16::from_str_radix(pid_s, 16).map_err(|_| UriError::InvalidUsbSelector)?;
    Ok(Uri::Usb(UsbSelector::VidPid { vid, pid }))
}
