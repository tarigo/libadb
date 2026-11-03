#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::ops::Range;

use bytes::Bytes;

use super::protocol::features::Feature;
use crate::error::ProtocolError;

/// Parsed CNXN identity banner: `<state>:<serial>:<prop>=<value>;...`.
///
/// `state` is the peer's connection state — `device` for a booted
/// system, but also `recovery`, `sideload`, `rescue`, `bootloader`,
/// or `host`. `serial` is usually empty (modern adbd leaves it blank).
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

    /// Connection state advertised by the peer: `device`, `recovery`,
    /// `sideload`, `rescue`, `bootloader`, ...
    pub fn state(&self) -> &str {
        self.str_at(&self.state)
    }

    /// Serial-number field of the banner; empty when the peer leaves
    /// it blank (as modern adbd does).
    pub fn serial(&self) -> &str {
        self.str_at(&self.serial)
    }

    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.iter().find_map(|(k, v)| {
            if self.str_at(k) == key {
                Some(self.str_at(v))
            } else {
                None
            }
        })
    }

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

    pub fn product_name(&self) -> Option<&str> {
        self.property("ro.product.name")
    }

    pub fn product_model(&self) -> Option<&str> {
        self.property("ro.product.model")
    }

    pub fn product_device(&self) -> Option<&str> {
        self.property("ro.product.device")
    }

    pub fn has_feature(&self, feature: &Feature) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    pub fn raw(&self) -> &[u8] {
        self.raw.as_ref()
    }

    fn str_at(&self, range: &Range<usize>) -> &str {
        // The ranges come from `range_of()` over substrings that
        // `str::split*` produced on this same buffer, so they sit on
        // code-point boundaries of text `parse_inner` validated; a
        // banner is a few hundred bytes read a handful of times, so
        // checking again costs nothing.
        core::str::from_utf8(&self.raw[range.clone()]).expect("banner ranges index validated UTF-8")
    }
}

fn range_of(base: &str, sub: &str) -> Range<usize> {
    let start = sub.as_ptr() as usize - base.as_ptr() as usize;
    start..start + sub.len()
}
