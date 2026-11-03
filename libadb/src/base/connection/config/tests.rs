use super::*;

#[test]
fn default_matches_adb_desktop_behaviour() {
    let c = ConnectionConfig::new();
    assert_eq!(c.max_payload(), MAX_PAYLOAD);
    assert_eq!(c.initial_ack_bytes(), INITIAL_DELAYED_ACK_BYTES);
    assert_eq!(c.max_rx_per_channel(), usize::MAX);
    assert_eq!(c.max_channels(), 32);
    assert_eq!(c.max_banner_properties(), 64);
    assert_eq!(ConnectionConfig::default(), c);
}

#[test]
fn embedded_preset_is_bounded() {
    let c = ConnectionConfig::embedded();
    assert_eq!(c.max_payload(), 8 * 1024);
    assert_eq!(c.initial_ack_bytes(), 32 * 1024);
    assert_eq!(c.max_rx_per_channel(), 64 * 1024);
    assert_eq!(c.max_channels(), 32);
    assert_eq!(c.max_banner_properties(), 64);
}

/// No slot at all would leave a connection that can open nothing.
#[test]
fn max_channels_is_clamped_to_one() {
    assert_eq!(
        ConnectionConfig::new().with_max_channels(0).max_channels(),
        1
    );
    assert_eq!(
        ConnectionConfig::new().with_max_channels(1).max_channels(),
        1
    );
    assert_eq!(
        ConnectionConfig::new().with_max_channels(5).max_channels(),
        5
    );
}

/// The table is allocated once the device's CNXN is in, so a size
/// the allocator cannot serve has to stop here: past this point it
/// is a panic or an abort, never an `Err`.
#[test]
fn max_channels_is_clamped_to_the_cap() {
    let cap = ConnectionConfig::MAX_CHANNELS;
    let clamped = |n| ConnectionConfig::new().with_max_channels(n).max_channels();

    assert_eq!(clamped(usize::MAX), cap);
    assert_eq!(clamped(cap + 1), cap);
    assert_eq!(clamped(cap), cap);
}

/// Both ends of the clamp stay usable in a `const`, which is what
/// rules `Ord::clamp` out.
#[test]
fn max_channels_clamp_works_in_const_context() {
    const FLOOR: ConnectionConfig = ConnectionConfig::new().with_max_channels(0);
    const CAP: ConnectionConfig = ConnectionConfig::new().with_max_channels(usize::MAX);

    assert_eq!(FLOOR.max_channels(), 1);
    assert_eq!(CAP.max_channels(), ConnectionConfig::MAX_CHANNELS);
}

/// Unlike the channel count, the property cap may be zero: a banner
/// with no properties is still a banner.
#[test]
fn max_banner_properties_is_kept_verbatim() {
    let c = ConnectionConfig::new().with_max_banner_properties(0);
    assert_eq!(c.max_banner_properties(), 0);
    let c = ConnectionConfig::new().with_max_banner_properties(3);
    assert_eq!(c.max_banner_properties(), 3);
}

#[test]
fn advertised_credit_never_exceeds_the_enforced_cap() {
    let c = ConnectionConfig::new()
        .with_initial_ack_bytes(32 * 1024 * 1024)
        .with_max_rx_per_channel(1024 * 1024);
    assert_eq!(c.advertised_ack_bytes(), 1024 * 1024);

    let unbounded = ConnectionConfig::new().with_initial_ack_bytes(32 * 1024 * 1024);
    assert_eq!(unbounded.advertised_ack_bytes(), 32 * 1024 * 1024);
}

#[test]
fn max_payload_is_clamped_to_the_protocol_maximum() {
    let c = ConnectionConfig::new().with_max_payload(MAX_PAYLOAD * 4);
    assert_eq!(c.max_payload(), MAX_PAYLOAD);
}

#[test]
fn max_payload_is_clamped_to_the_minimum() {
    let c = ConnectionConfig::new().with_max_payload(0);
    assert_eq!(c.max_payload(), MIN_MAX_PAYLOAD);
}

#[test]
fn max_payload_in_range_is_kept_verbatim() {
    let c = ConnectionConfig::new().with_max_payload(8 * 1024);
    assert_eq!(c.max_payload(), 8 * 1024);
}

#[test]
fn rx_cap_never_falls_below_one_payload() {
    let c = ConnectionConfig::new()
        .with_max_payload(8 * 1024)
        .with_max_rx_per_channel(1024);
    assert_eq!(c.rx_cap(), 8 * 1024);
}

#[test]
fn rx_cap_uses_the_configured_value_when_larger() {
    let c = ConnectionConfig::new()
        .with_max_payload(8 * 1024)
        .with_max_rx_per_channel(64 * 1024);
    assert_eq!(c.rx_cap(), 64 * 1024);
}

#[test]
fn builder_is_usable_in_const_context() {
    const C: ConnectionConfig = ConnectionConfig::embedded()
        .with_max_payload(4 * 1024)
        .with_max_channels(4)
        .with_max_banner_properties(8);
    assert_eq!(C.max_payload(), 4 * 1024);
    assert_eq!(C.initial_ack_bytes(), 32 * 1024);
    assert_eq!(C.max_channels(), 4);
    assert_eq!(C.max_banner_properties(), 8);
}
