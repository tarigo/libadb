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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::error::ProtocolError;

    use super::super::{device_banner::DeviceBanner, protocol::features::Feature};

    /// A property cap no banner below reaches unless it tests the cap.
    const ROOM: usize = 8;

    fn banner(text: &'static str) -> DeviceBanner {
        DeviceBanner::from_bytes(Bytes::from_static(text.as_bytes()), ROOM).unwrap()
    }

    #[test]
    fn parses_basic_properties_and_features() {
        let banner = banner(
            "device::ro.product.name=panther;ro.product.model=Pixel 7;ro.product.device=panther;features=shell_v2,cmd,stat_v2"
        );

        assert_eq!(banner.product_name(), Some("panther"));
        assert_eq!(banner.product_model(), Some("Pixel 7"));
        assert_eq!(banner.product_device(), Some("panther"));

        assert!(banner.has_feature(&Feature::ShellV2));
        assert!(banner.has_feature(&Feature::Cmd));
        assert!(banner.has_feature(&Feature::StatV2));
        assert!(!banner.has_feature(&Feature::LsV2));
    }

    #[test]
    fn parses_generic_property_lookup() {
        let banner =
            banner("device::ro.build.version.release=14;ro.product.name=panther;features=shell_v2");

        assert_eq!(banner.property("ro.build.version.release"), Some("14"));
        assert_eq!(banner.property("ro.product.name"), Some("panther"));
        assert_eq!(banner.property("does.not.exist"), None);
    }

    #[test]
    fn accepts_empty_features_value() {
        let banner = banner("device::ro.product.name=panther;features=");

        assert_eq!(banner.product_name(), Some("panther"));
        assert!(!banner.has_feature(&Feature::ShellV2));
        assert!(banner.features().is_empty());
    }

    #[test]
    fn ignores_unknown_features() {
        let banner =
            banner("device::ro.product.name=panther;features=shell_v2,totally_unknown_feature,cmd");

        assert!(banner.has_feature(&Feature::ShellV2));
        assert!(banner.has_feature(&Feature::Cmd));
        assert!(!banner.has_feature(&Feature::StatV2));
        assert_eq!(banner.features().len(), 2);
    }

    #[test]
    fn ignores_empty_feature_entries() {
        let banner = banner("device::ro.product.name=panther;features=shell_v2,,cmd,");

        assert!(banner.has_feature(&Feature::ShellV2));
        assert!(banner.has_feature(&Feature::Cmd));
        assert_eq!(banner.features().len(), 2);
    }

    #[test]
    fn keeps_zero_copy_source_bytes_accessible() {
        let raw = Bytes::from_static(b"device::ro.product.name=panther;features=shell_v2");

        let banner = DeviceBanner::from_bytes(raw.clone(), ROOM).unwrap();

        assert_eq!(banner.raw(), raw.as_ref());
        assert_eq!(banner.product_name(), Some("panther"));
    }

    #[test]
    fn returns_invalid_prefix_when_colons_are_missing() {
        for bad in ["device", "device:serial-without-banner-part", "garbage"] {
            let err =
                DeviceBanner::from_bytes(Bytes::from_static(bad.as_bytes()), ROOM).unwrap_err();

            assert_eq!(err, ProtocolError::InvalidBannerPrefix, "banner: {bad}");
        }
    }

    #[test]
    fn exposes_state_and_empty_serial() {
        let banner = banner("device::features=shell_v2");

        assert_eq!(banner.state(), "device");
        assert_eq!(banner.serial(), "");
    }

    #[test]
    fn accepts_non_device_states() {
        let recovery = banner("recovery::features=shell_v2");
        assert_eq!(recovery.state(), "recovery");
        assert!(recovery.has_feature(&Feature::ShellV2));

        let sideload = banner("sideload::");
        assert_eq!(sideload.state(), "sideload");
        assert!(sideload.features().is_empty());

        let host = banner("host::ro.product.name=panther;features=shell_v2");
        assert_eq!(host.state(), "host");
        assert_eq!(host.product_name(), Some("panther"));
    }

    #[test]
    fn parses_nonempty_serial_field() {
        let banner = banner("device:0123456789ABCDEF:ro.product.name=panther");

        assert_eq!(banner.state(), "device");
        assert_eq!(banner.serial(), "0123456789ABCDEF");
        assert_eq!(banner.product_name(), Some("panther"));
    }

    #[test]
    fn returns_invalid_utf8() {
        let err = DeviceBanner::from_bytes(
            Bytes::from_static(b"device::ro.product.name=\xFF;features=shell_v2"),
            ROOM,
        )
        .unwrap_err();

        assert_eq!(err, ProtocolError::InvalidBannerUtf8);
    }

    #[test]
    fn returns_invalid_key_value_for_malformed_property() {
        let err = DeviceBanner::from_bytes(
            Bytes::from_static(b"device::ro.product.name=panther;broken_entry;features=shell_v2"),
            ROOM,
        )
        .unwrap_err();

        assert_eq!(err, ProtocolError::InvalidBannerKeyValue);
    }

    #[test]
    fn returns_too_many_properties() {
        let err = DeviceBanner::from_bytes(
            Bytes::from_static(b"device::a=1;b=2;c=3;features=shell_v2"),
            2,
        )
        .unwrap_err();

        assert_eq!(err, ProtocolError::TooManyBannerProperties);
    }

    /// The cap is how many pairs fit, not one short of it, and the
    /// `features=` entry does not count against it.
    #[test]
    fn accepts_exactly_max_properties() {
        let banner =
            DeviceBanner::from_bytes(Bytes::from_static(b"device::a=1;b=2;features=shell_v2"), 2)
                .unwrap();

        assert_eq!(banner.properties().count(), 2);
        assert!(banner.has_feature(&Feature::ShellV2));
    }

    /// A feature named again, in the same entry or another, is listed
    /// once, where it first appeared: that is what keeps the list as
    /// short as `Feature` has variants, whatever the device sends.
    #[test]
    fn lists_a_repeated_feature_once() {
        let banner = banner("device::features=shell_v2,cmd,shell_v2;features=cmd,shell_v2");

        assert_eq!(banner.features(), [Feature::ShellV2, Feature::Cmd]);
    }

    #[test]
    fn properties_iterator_returns_all_properties() {
        let banner =
            banner("device::ro.product.name=panther;ro.product.model=Pixel 7;features=shell_v2");

        let collected: alloc::vec::Vec<(&str, &str)> = banner.properties().collect();

        assert!(collected.contains(&("ro.product.name", "panther")));
        assert!(collected.contains(&("ro.product.model", "Pixel 7")));
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn supports_duplicate_keys_and_returns_first_match() {
        let banner =
            banner("device::ro.product.name=first;ro.product.name=second;features=shell_v2");

        assert_eq!(banner.property("ro.product.name"), Some("first"));
    }

    #[test]
    fn accepts_banner_without_properties_only_features() {
        let banner = banner("device::features=shell_v2,cmd");

        assert_eq!(banner.product_name(), None);
        assert!(banner.has_feature(&Feature::ShellV2));
        assert!(banner.has_feature(&Feature::Cmd));
    }

    #[test]
    fn accepts_banner_without_features_only_properties() {
        let banner = banner("device::ro.product.name=panther;ro.product.model=Pixel 7");

        assert_eq!(banner.product_name(), Some("panther"));
        assert_eq!(banner.product_model(), Some("Pixel 7"));
        assert!(!banner.has_feature(&Feature::ShellV2));
    }
}
