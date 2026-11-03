use bytes::Bytes;

use crate::error::ProtocolError;

use super::super::{
    device_banner::{DeviceBanner, DeviceState},
    protocol::features::Feature,
};

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
        let err = DeviceBanner::from_bytes(Bytes::from_static(bad.as_bytes()), ROOM).unwrap_err();

        assert_eq!(err, ProtocolError::InvalidBannerPrefix, "banner: {bad}");
    }
}

#[test]
fn exposes_state_and_empty_serial() {
    let banner = banner("device::features=shell_v2");

    assert_eq!(banner.state(), DeviceState::Device);
    assert_eq!(banner.state_str(), "device");
    assert_eq!(banner.serial(), "");
}

#[test]
fn accepts_non_device_states() {
    let recovery = banner("recovery::features=shell_v2");
    assert_eq!(recovery.state(), DeviceState::Recovery);
    assert!(recovery.has_feature(&Feature::ShellV2));

    let sideload = banner("sideload::");
    assert_eq!(sideload.state(), DeviceState::Sideload);
    assert!(sideload.features().is_empty());

    let host = banner("host::ro.product.name=panther;features=shell_v2");
    assert_eq!(host.state(), DeviceState::Host);
    assert_eq!(host.product_name(), Some("panther"));
}

#[test]
fn names_every_documented_state() {
    for (text, state) in [
        ("device", DeviceState::Device),
        ("recovery", DeviceState::Recovery),
        ("sideload", DeviceState::Sideload),
        ("rescue", DeviceState::Rescue),
        ("bootloader", DeviceState::Bootloader),
        ("host", DeviceState::Host),
    ] {
        let raw = alloc::format!("{text}::");
        let parsed = DeviceBanner::from_bytes(Bytes::from(raw.into_bytes()), ROOM).unwrap();
        assert_eq!(parsed.state(), state, "{text}");
    }
}

#[test]
fn an_unnamed_state_is_other_and_keeps_its_text() {
    let banner = banner("offline::");

    assert_eq!(banner.state(), DeviceState::Other);
    assert_eq!(banner.state_str(), "offline");
}

#[test]
fn parses_nonempty_serial_field() {
    let banner = banner("device:0123456789ABCDEF:ro.product.name=panther");

    assert_eq!(banner.state(), DeviceState::Device);
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
    let banner = banner("device::ro.product.name=first;ro.product.name=second;features=shell_v2");

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
