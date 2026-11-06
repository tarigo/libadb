#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::ops::Range;

use bytes::Bytes;

use super::protocol::features::Feature;
use crate::error::ProtocolError;

/// The connection state a peer names first in its banner, read by
/// [`DeviceBanner::state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviceState {
    /// `device`: a booted system.
    Device,
    /// `recovery`: the recovery image.
    Recovery,
    /// `sideload`: recovery waiting for `adb sideload`.
    Sideload,
    /// `rescue`: the rescue mode of recovery.
    Rescue,
    /// `bootloader`: the bootloader.
    Bootloader,
    /// `host`: another ADB host rather than a device.
    Host,
    /// A state this version of libadb does not name. Compare
    /// [`DeviceBanner::state_str`] rather than matching this variant: a
    /// later libadb may name the state.
    Other,
}

impl DeviceState {
    fn named(state: &str) -> Self {
        match state {
            "device" => Self::Device,
            "recovery" => Self::Recovery,
            "sideload" => Self::Sideload,
            "rescue" => Self::Rescue,
            "bootloader" => Self::Bootloader,
            "host" => Self::Host,
            _ => Self::Other,
        }
    }
}

/// Parsed CNXN identity banner: `<state>:<serial>:<prop>=<value>;...`.
///
/// `state` is the peer's connection state, a [`DeviceState`] — `device`
/// for a booted system, but also `recovery`, `sideload`, `rescue`,
/// `bootloader`, or `host`. `serial` is usually empty (modern adbd
/// leaves it blank).
#[derive(Debug, Clone)]
pub struct DeviceBanner {
    raw: Bytes,
    state: Range<usize>,
    serial: Range<usize>,
    properties: Vec<(Range<usize>, Range<usize>)>,
    features: Vec<Feature>,
}

impl DeviceBanner {
    /// Parse a banner that may carry at most `max_properties`
    /// `key=value` pairs.
    ///
    /// The `features=` entry is not one of them. A feature named twice
    /// is kept once and one this library does not know is skipped, so
    /// that list grows no longer than [`Feature`] has variants.
    ///
    /// # Errors
    ///
    /// - [`ProtocolError::InvalidBannerUtf8`] when `raw` is not UTF-8;
    /// - [`ProtocolError::InvalidBannerPrefix`] when it lacks the
    ///   `<state>:<serial>:` prefix;
    /// - [`ProtocolError::InvalidBannerKeyValue`] for an entry with no
    ///   `=`;
    /// - [`ProtocolError::TooManyBannerProperties`] past
    ///   `max_properties` pairs.
    pub fn from_bytes(raw: impl Into<Bytes>, max_properties: usize) -> Result<Self, ProtocolError> {
        Self::parse_inner(raw.into(), max_properties)
    }

    fn parse_inner(raw: Bytes, max_properties: usize) -> Result<Self, ProtocolError> {
        let s = core::str::from_utf8(raw.as_ref()).map_err(|_| ProtocolError::InvalidBannerUtf8)?;
        let (state, rest) = s
            .split_once(':')
            .ok_or(ProtocolError::InvalidBannerPrefix)?;
        let (serial, payload) = rest
            .split_once(':')
            .ok_or(ProtocolError::InvalidBannerPrefix)?;

        let mut properties = Vec::new();
        let mut features = Vec::new();

        for part in payload.split(';') {
            if part.is_empty() {
                continue;
            }

            let (key, value) = part
                .split_once('=')
                .ok_or(ProtocolError::InvalidBannerKeyValue)?;

            if key == "features" {
                for f in value.split(',') {
                    match Feature::try_from(f) {
                        Ok(feature) => {
                            if !features.contains(&feature) {
                                features.push(feature);
                            }
                        }
                        Err(_) => {
                            log::warn!("Unknown feature: {}", f);
                        }
                    }
                }
            } else {
                if properties.len() == max_properties {
                    return Err(ProtocolError::TooManyBannerProperties);
                }
                properties.push((range_of(s, key), range_of(s, value)));
            }
        }

        let state = range_of(s, state);
        let serial = range_of(s, serial);
        Ok(Self {
            raw,
            state,
            serial,
            properties,
            features,
        })
    }

    /// Connection state advertised by the peer; one libadb does not
    /// name is [`DeviceState::Other`], and
    /// [`state_str`](Self::state_str) still has its text.
    pub fn state(&self) -> DeviceState {
        DeviceState::named(self.state_str())
    }

    /// Connection state as the banner spells it: `device`, `recovery`,
    /// `sideload`, `rescue`, `bootloader`, `host`, or whatever else a
    /// peer sends.
    pub fn state_str(&self) -> &str {
        self.str_at(&self.state)
    }

    /// Serial-number field of the banner; empty when the peer leaves
    /// it blank (as modern adbd does).
    pub fn serial(&self) -> &str {
        self.str_at(&self.serial)
    }

    /// The value of the first property named `key`, if any.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.iter().find_map(|(k, v)| {
            if self.str_at(k) == key {
                Some(self.str_at(v))
            } else {
                None
            }
        })
    }

    /// Every `key=value` property, in banner order and repeats included;
    /// the `features=` entry is not one of them.
    pub fn properties(&self) -> impl Iterator<Item = (&str, &str)> {
        self.properties
            .iter()
            .map(|(k, v)| (self.str_at(k), self.str_at(v)))
    }

    /// Features the device advertised that this library knows, each
    /// once, in the order the banner first names them.
    pub fn features(&self) -> &[Feature] {
        self.features.as_slice()
    }

    /// The `ro.product.name` property, if the banner carries it.
    pub fn product_name(&self) -> Option<&str> {
        self.property("ro.product.name")
    }

    /// The `ro.product.model` property, if the banner carries it.
    pub fn product_model(&self) -> Option<&str> {
        self.property("ro.product.model")
    }

    /// The `ro.product.device` property, if the banner carries it.
    pub fn product_device(&self) -> Option<&str> {
        self.property("ro.product.device")
    }

    /// Whether `feature` is among [`features`](Self::features).
    pub fn has_feature(&self, feature: &Feature) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// The bytes the banner was parsed from, as they were given.
    pub fn raw(&self) -> &[u8] {
        self.raw.as_ref()
    }

    fn str_at(&self, range: &Range<usize>) -> &str {
        core::str::from_utf8(&self.raw[range.clone()]).expect("banner ranges index validated UTF-8")
    }
}

fn range_of(base: &str, sub: &str) -> Range<usize> {
    let start = sub.as_ptr() as usize - base.as_ptr() as usize;
    start..start + sub.len()
}
