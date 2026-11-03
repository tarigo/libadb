use crate::base::protocol::constant::MAX_PAYLOAD;
use crate::base::protocol::features::INITIAL_DELAYED_ACK_BYTES;

/// Smallest payload size a connection may advertise.
///
/// The v1 protocol used 4 KiB packets and adbd still assumes a few
/// hundred bytes fit in one message (service destinations, banners), so
/// anything below this is a configuration mistake rather than a tuning
/// choice.
pub const MIN_MAX_PAYLOAD: u32 = 1024;

/// Per-connection resource limits.
///
/// Every field bounds memory the library may allocate while a
/// connection is live. The defaults ([`ConnectionConfig::new`]) match
/// what `adb` itself uses on a desktop host; [`ConnectionConfig::embedded`]
/// trades throughput for a footprint that fits a microcontroller.
///
/// ```ignore
/// use libadb::{Connection, ConnectionConfig, Feature};
///
/// let config = ConnectionConfig::embedded().with_max_payload(4 * 1024);
/// let conn = Connection::connect_with_config(
///     transport, auth, &[Feature::ShellV2], config,
/// ).await?;
/// ```
///
/// # Why this matters off the desktop
///
/// `max_payload` is announced to the device in the CNXN handshake, and
/// adbd honours it: it never sends a WRTE larger than the value the host
/// advertised. Keeping the default 1 MiB therefore *invites* megabyte
/// packets, and the receive buffer has to hold each one whole. With
/// only a few hundred KiB of RAM that is fatal; 8 KiB packets are not.
///
/// `max_channels` sizes the channel table, which is allocated whole
/// when the connection is made: every slot costs about a hundred bytes
/// whether a channel ever uses it or not. Both presets make room for
/// [`DEFAULT_MAX_CHANNELS`](Self::DEFAULT_MAX_CHANNELS); a
/// microcontroller that never has more than a few channels open can
/// lower it with [`with_max_channels`](Self::with_max_channels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionConfig {
    max_payload: u32,
    initial_ack_bytes: u32,
    max_rx_per_channel: usize,
    max_channels: usize,
    max_banner_properties: usize,
}

impl ConnectionConfig {
    /// Channels both presets make room for; see
    /// [`with_max_channels`](Self::with_max_channels).
    pub const DEFAULT_MAX_CHANNELS: usize = 32;

    /// Device-banner properties both presets accept; see
    /// [`with_max_banner_properties`](Self::with_max_banner_properties).
    pub const DEFAULT_MAX_BANNER_PROPERTIES: usize = 64;

    /// Desktop defaults: 1 MiB payloads, 32 MiB of delayed-ACK credit,
    /// unbounded per-channel buffering — the behaviour of `adb` itself —
    /// with [`DEFAULT_MAX_CHANNELS`](Self::DEFAULT_MAX_CHANNELS) channels
    /// and [`DEFAULT_MAX_BANNER_PROPERTIES`](Self::DEFAULT_MAX_BANNER_PROPERTIES)
    /// banner properties.
    pub const fn new() -> Self {
        Self {
            max_payload: MAX_PAYLOAD,
            initial_ack_bytes: INITIAL_DELAYED_ACK_BYTES,
            max_rx_per_channel: usize::MAX,
            max_channels: Self::DEFAULT_MAX_CHANNELS,
            max_banner_properties: Self::DEFAULT_MAX_BANNER_PROPERTIES,
        }
    }

    /// Microcontroller-friendly preset: 8 KiB payloads, 32 KiB of
    /// delayed-ACK credit, 64 KiB of per-channel buffering. Channel and
    /// banner-property limits are those of [`new`](Self::new).
    ///
    /// Sized so that a connection with a handful of channels stays well
    /// inside a few hundred KiB of heap.
    pub const fn embedded() -> Self {
        Self {
            max_payload: 8 * 1024,
            initial_ack_bytes: 32 * 1024,
            max_rx_per_channel: 64 * 1024,
            max_channels: Self::DEFAULT_MAX_CHANNELS,
            max_banner_properties: Self::DEFAULT_MAX_BANNER_PROPERTIES,
        }
    }

    /// Largest payload this host advertises in CNXN and accepts from the
    /// device. Clamped to `[MIN_MAX_PAYLOAD, MAX_PAYLOAD]`.
    ///
    /// A device packet exceeding this value is rejected with
    /// [`ProtocolError::PayloadTooLarge`](crate::error::ProtocolError::PayloadTooLarge)
    /// instead of being buffered.
    pub const fn with_max_payload(mut self, bytes: u32) -> Self {
        self.max_payload = if bytes > MAX_PAYLOAD {
            MAX_PAYLOAD
        } else if bytes < MIN_MAX_PAYLOAD {
            MIN_MAX_PAYLOAD
        } else {
            bytes
        };
        self
    }

    /// Delayed-ACK credit granted to the device when a channel opens
    /// (`OPEN.arg1`), i.e. how many unacknowledged bytes it may send.
    ///
    /// Only meaningful when both peers advertise `delayed_ack`.
    pub const fn with_initial_ack_bytes(mut self, bytes: u32) -> Self {
        self.initial_ack_bytes = bytes;
        self
    }

    /// Hard cap on bytes buffered for a single channel that nobody is
    /// currently reading.
    ///
    /// Backpressure normally keeps a channel well under this: see
    /// [`rx_watermark`](Self::rx_watermark). Hitting the cap means the
    /// device wrote past a window that was never re-opened.
    ///
    /// A fuse, not flow control. Crossing it drops the WRTE that did
    /// not fit and fails the call that observed it with
    /// [`Error::ChannelRxOverflow`](crate::Error::ChannelRxOverflow).
    /// That packet is never acknowledged, so the device stalls on this
    /// channel — it waits for an OKAY that will not come, or never gets
    /// the credit back under delayed ACK. Other channels and the
    /// connection stay usable, but this channel's byte stream now has a
    /// gap. The error surfaces on whichever call is driving the
    /// connection, which may be a read on a different channel. On a
    /// split connection driven by [`Reader::run`](crate::Reader::run)
    /// it lands on this channel instead, which `run` closes. The
    /// effective cap is never below [`max_payload`](Self::max_payload),
    /// so one legal packet always fits.
    pub const fn with_max_rx_per_channel(mut self, bytes: usize) -> Self {
        self.max_rx_per_channel = bytes;
        self
    }

    /// How many channels may be open at once, whichever side opened
    /// them. Clamped to at least 1: with no slot, nothing could open.
    ///
    /// The table holds this many slots from the moment the connection
    /// is made. With all of them taken, opening another fails with
    /// [`Error::NoFreeChannels`](crate::Error::NoFreeChannels), as does
    /// accepting a device-initiated one. The same number bounds the
    /// device-initiated OPENs still waiting for a verdict: past it, a
    /// new one is refused with CLSE as it arrives.
    pub const fn with_max_channels(mut self, n: usize) -> Self {
        self.max_channels = if n == 0 { 1 } else { n };
        self
    }

    /// Most `key=value` properties the device's CNXN banner may carry;
    /// one more fails the handshake with
    /// [`ProtocolError::TooManyBannerProperties`](crate::error::ProtocolError::TooManyBannerProperties).
    ///
    /// The `features=` entry is not counted. adbd sends three
    /// (`ro.product.name`, `ro.product.model`, `ro.product.device`), so
    /// zero turns every real device away. The cap exists because each
    /// property costs the parsed banner more than its few bytes on the
    /// wire: without it a peer could fill one packet with empty ones.
    pub const fn with_max_banner_properties(mut self, n: usize) -> Self {
        self.max_banner_properties = n;
        self
    }

    /// Largest payload advertised to the device.
    pub const fn max_payload(&self) -> u32 {
        self.max_payload
    }

    /// Delayed-ACK credit granted per channel.
    pub const fn initial_ack_bytes(&self) -> u32 {
        self.initial_ack_bytes
    }

    /// Configured per-channel buffering cap, before the `max_payload`
    /// floor is applied.
    pub const fn max_rx_per_channel(&self) -> usize {
        self.max_rx_per_channel
    }

    /// Slots in the channel table.
    pub const fn max_channels(&self) -> usize {
        self.max_channels
    }

    /// Most properties the device banner may carry.
    pub const fn max_banner_properties(&self) -> usize {
        self.max_banner_properties
    }

    /// How much unread data a channel may hold before acknowledgements
    /// start waiting for the application to read.
    ///
    /// Acknowledging an inbound write is what re-opens the sender's
    /// window, so acknowledging on arrival lets a device keep writing to
    /// a channel nobody reads. The ceiling comes from what was already
    /// promised: the device was told it may send
    /// [`initial_ack_bytes`](Self::initial_ack_bytes) before waiting, so
    /// that is the natural bound on what may pile up — clamped to the
    /// enforced per-channel cap, and never below `max_payload`, which a
    /// single packet would otherwise trip.
    ///
    /// Only consulted without delayed-ack. With it, credit is returned
    /// as bytes are read and the advertised budget is the bound.
    pub const fn rx_watermark(&self) -> usize {
        let want = if self.initial_ack_bytes as usize > self.max_payload as usize {
            self.initial_ack_bytes as usize
        } else {
            self.max_payload as usize
        };
        let ceiling = self.rx_cap();
        if want > ceiling {
            ceiling
        } else {
            want
        }
    }

    /// Per-channel buffering cap actually enforced: never smaller than
    /// one full payload.
    pub(crate) const fn rx_cap(&self) -> usize {
        if self.max_rx_per_channel < self.max_payload as usize {
            self.max_payload as usize
        } else {
            self.max_rx_per_channel
        }
    }

    /// Delayed-ACK credit OPEN actually advertises:
    /// [`initial_ack_bytes`](Self::initial_ack_bytes) clamped to
    /// [`rx_cap`](Self::rx_cap). Advertising more would invite a
    /// compliant device to overflow the buffer it was promised.
    pub(crate) const fn advertised_ack_bytes(&self) -> u32 {
        let cap = self.rx_cap();
        if self.initial_ack_bytes as usize > cap {
            // `cap` fits: it is below a u32 here.
            cap as u32
        } else {
            self.initial_ack_bytes
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
