//! What the handshake settled for the life of a connection.

use super::connection::ConnectionConfig;
use super::device_banner::DeviceBanner;
use super::error::{Error, ProtocolError};
use super::protocol::command;
use super::protocol::features::{self, Feature};
use super::protocol::{Checksum, Packet};

/// How inbound data is acknowledged, fixed by the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckMode {
    /// A window of one packet: every WRTE is answered with an empty
    /// OKAY.
    Classic,
    /// Credit-based: each OKAY hands back the bytes it acknowledges.
    Delayed,
}

/// What a channel's receive side goes by: how it acknowledges and how
/// much unread data it may hold.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RxPolicy {
    /// How inbound writes are acknowledged.
    pub(crate) ack: AckMode,
    /// Unread data a channel may hold; a WRTE past it is an overflow
    /// rather than a bigger buffer.
    pub(crate) rx_cap: usize,
    /// Unread data past which a classic acknowledgement waits for a
    /// read; see [`ConnectionConfig::rx_watermark`].
    pub(crate) watermark: usize,
}

/// What the CNXN exchange settled: fixed once the device's CNXN is in,
/// and the same for a [`Connection`](crate::Connection) and both of its
/// split halves.
pub(crate) struct Negotiated {
    /// Largest outbound payload: the device's offer, bounded by what
    /// this library can encode.
    pub(crate) max_payload: u32,
    /// `min(ADB_VERSION, device version)`.
    pub(crate) protocol_version: u32,
    /// The limits the connection was opened with.
    pub(crate) config: ConnectionConfig,
    /// Whether both banners named delayed ACK.
    pub(crate) delayed_ack: bool,
    /// The device's banner, parsed.
    pub(crate) device_banner: Option<DeviceBanner>,
}

impl Negotiated {
    /// Settle on what `host_banner`, the payload of our CNXN, and the
    /// device's `cnxn` agree on.
    pub(crate) fn new(
        host_banner: &[u8],
        cnxn: Packet,
        config: ConnectionConfig,
    ) -> Result<Self, ProtocolError> {
        let delayed_ack = features::has_feature(host_banner, features::DELAYED_ACK)
            && features::has_feature(&cnxn.data, features::DELAYED_ACK);
        let device_banner = DeviceBanner::from_bytes(cnxn.data, config.max_banner_properties())?;
        Ok(Self {
            max_payload: cnxn.arg1.min(command::MAX_PAYLOAD),
            protocol_version: cnxn.arg0.min(command::ADB_VERSION),
            config,
            delayed_ack,
            device_banner: Some(device_banner),
        })
    }

    /// How this connection acknowledges inbound data.
    pub(crate) fn ack_mode(&self) -> AckMode {
        if self.delayed_ack {
            AckMode::Delayed
        } else {
            AckMode::Classic
        }
    }

    /// What every channel's receive side goes by on this connection.
    pub(crate) fn rx_policy(&self) -> RxPolicy {
        RxPolicy {
            ack: self.ack_mode(),
            rx_cap: self.config.rx_cap(),
            watermark: self.config.rx_watermark(),
        }
    }

    /// Whether outgoing packets carry a payload checksum.
    pub(crate) fn checksum(&self) -> Checksum {
        Checksum::for_version(self.protocol_version)
    }

    /// The receive credit our OPEN and READY advertise. `None` without
    /// delayed ACK: OPEN's `arg1` is then zero and READY carries no
    /// payload.
    pub(crate) fn advertised_credit(&self) -> Option<u32> {
        self.delayed_ack.then(|| self.config.advertised_ack_bytes())
    }

    /// Whether the device listed `feature` in its banner, or `None`
    /// when no banner was parsed.
    pub(crate) fn advertises(&self, feature: &Feature) -> Option<bool> {
        self.device_banner.as_ref().map(|b| b.has_feature(feature))
    }

    /// Fail with [`Error::MissingFeature`] if the banner was parsed and
    /// does not list `feature`; a connection without one passes.
    pub(crate) fn require_feature<E>(&self, feature: Feature) -> Result<(), Error<E>> {
        match self.advertises(&feature) {
            Some(false) => Err(Error::MissingFeature(feature)),
            _ => Ok(()),
        }
    }
}
