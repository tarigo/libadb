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
/// let conn = Connection::<_>::connect_with_config(
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionConfig {
    max_payload: u32,
    initial_ack_bytes: u32,
    max_rx_per_channel: usize,
}

impl ConnectionConfig {
    /// Desktop defaults: 1 MiB payloads, 32 MiB of delayed-ACK credit,
    /// unbounded per-channel buffering — the behaviour of `adb` itself.
    pub const fn new() -> Self {
        Self {
            max_payload: MAX_PAYLOAD,
            initial_ack_bytes: INITIAL_DELAYED_ACK_BYTES,
            max_rx_per_channel: usize::MAX,
        }
    }

    /// Microcontroller-friendly preset: 8 KiB payloads, 32 KiB of
    /// delayed-ACK credit, 64 KiB of per-channel buffering.
    ///
    /// Sized so that a connection with a handful of channels stays well
    /// inside a few hundred KiB of heap.
    pub const fn embedded() -> Self {
        Self {
            max_payload: 8 * 1024,
            initial_ack_bytes: 32 * 1024,
            max_rx_per_channel: 64 * 1024,
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
    /// connection, which may be a read on a different channel. The
    /// effective cap is never below [`max_payload`](Self::max_payload),
    /// so one legal packet always fits.
    pub const fn with_max_rx_per_channel(mut self, bytes: usize) -> Self {
        self.max_rx_per_channel = bytes;
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
        assert_eq!(ConnectionConfig::default(), c);
    }

    #[test]
    fn embedded_preset_is_bounded() {
        let c = ConnectionConfig::embedded();
        assert_eq!(c.max_payload(), 8 * 1024);
        assert_eq!(c.initial_ack_bytes(), 32 * 1024);
        assert_eq!(c.max_rx_per_channel(), 64 * 1024);
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
        const C: ConnectionConfig = ConnectionConfig::embedded().with_max_payload(4 * 1024);
        assert_eq!(C.max_payload(), 4 * 1024);
        assert_eq!(C.initial_ack_bytes(), 32 * 1024);
    }
}
