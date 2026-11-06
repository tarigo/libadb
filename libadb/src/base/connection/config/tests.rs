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
        .with_max_payload(8 * 1024)
        .with_initial_ack_bytes(32 * 1024 * 1024)
        .with_max_rx_per_channel(1024 * 1024);
    assert_eq!(c.advertised_ack_bytes(), 1024 * 1024 - 8 * 1024 + 1);

    let unbounded = ConnectionConfig::new().with_initial_ack_bytes(32 * 1024 * 1024);
    assert_eq!(unbounded.advertised_ack_bytes(), 32 * 1024 * 1024);
}

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;

/// The ceiling of a 1 KiB packet under a cap of `u32::MAX`, which is also
/// `usize::MAX` on a 32-bit target.
const TOP: usize = u32::MAX as usize - 1023;

/// `max_payload`, `initial_ack_bytes`, `max_rx_per_channel`, and the
/// `rx_watermark` and `advertised_ack_bytes` they come to.
const LIMITS: [(u32, u32, usize, usize, u32); 12] = [
    // The cap is one packet, or would be less.
    (KIB, 32 * MIB, 1, 1, 1),
    (KIB, 32 * MIB, 1024, 1, 1),
    (MIB, 32 * MIB, 1024 * 1024, 1, 1),
    // Each byte of cap past a packet is one more of either.
    (KIB, 32 * MIB, 1025, 2, 2),
    (KIB, 32 * MIB, 2048, 1025, 1025),
    // Around the clamp.
    (KIB, 1024, 2048, 1024, 1024),
    (KIB, 1025, 2048, 1025, 1025),
    (KIB, 1026, 2048, 1025, 1025),
    // Credit under a packet is kept; the watermark is not below one.
    (4 * KIB, KIB, 64 * 1024, 4096, 1024),
    // No cap to speak of.
    (MIB, 32 * MIB, usize::MAX, 32 << 20, 32 * MIB),
    (KIB, TOP as u32, usize::MAX, TOP, TOP as u32),
    // A ceiling as wide as the credit's field.
    (KIB, u32::MAX, u32::MAX as usize, TOP, TOP as u32),
];

fn config(max_payload: u32, credit: u32, cap: usize) -> ConnectionConfig {
    ConnectionConfig::new()
        .with_max_payload(max_payload)
        .with_initial_ack_bytes(credit)
        .with_max_rx_per_channel(cap)
}

#[test]
fn both_limits_stop_one_packet_short_of_the_cap() {
    for (max_payload, credit, cap, watermark, advertised) in LIMITS {
        let c = config(max_payload, credit, cap);
        let row = (max_payload, credit, cap);
        assert_eq!(c.rx_watermark(), watermark, "{row:?}");
        assert_eq!(c.advertised_ack_bytes(), advertised, "{row:?}");
    }
}

/// A device acknowledged one byte short of the watermark, or left with
/// one byte of credit, may send a full packet.
#[test]
fn neither_limit_lets_a_full_packet_past_the_cap() {
    for (max_payload, credit, cap, _, _) in LIMITS {
        let c = config(max_payload, credit, cap);
        let row = (max_payload, credit, cap);
        let room = c.rx_cap() - max_payload as usize;
        assert!(c.rx_watermark() >= 1, "{row:?}");
        assert!(c.advertised_ack_bytes() >= 1, "{row:?}");
        assert!(c.rx_watermark() - 1 <= room, "{row:?}");
        assert!(c.advertised_ack_bytes() as usize - 1 <= room, "{row:?}");
    }
}

#[test]
fn the_presets_keep_their_limits() {
    let desktop = ConnectionConfig::new();
    assert_eq!(desktop.rx_watermark(), 32 * 1024 * 1024);
    assert_eq!(desktop.advertised_ack_bytes(), 32 * 1024 * 1024);

    let embedded = ConnectionConfig::embedded();
    assert_eq!(embedded.rx_watermark(), 32 * 1024);
    assert_eq!(embedded.advertised_ack_bytes(), 32 * 1024);
}

/// An overflow in these would stop the build rather than wrap.
#[test]
fn the_limits_work_in_const_context_with_no_cap_at_all() {
    const WIDEST: ConnectionConfig = ConnectionConfig::new()
        .with_max_payload(KIB)
        .with_initial_ack_bytes(TOP as u32)
        .with_max_rx_per_channel(usize::MAX);
    const WATERMARK: usize = WIDEST.rx_watermark();
    const CREDIT: u32 = WIDEST.advertised_ack_bytes();

    assert_eq!(WATERMARK, TOP);
    assert_eq!(CREDIT, TOP as u32);
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
