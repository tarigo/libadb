use super::connection::ConnectionConfig;
use super::device_banner::DeviceBanner;
use super::protocol::command;
use super::protocol::features::Feature;
use super::protocol::{Checksum, Packet};
use crate::error::{Error, ProtocolError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckMode {
    Classic,
    Delayed,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RxPolicy {
    pub(crate) ack: AckMode,
    pub(crate) rx_cap: usize,
    pub(crate) watermark: usize,
}

pub(crate) struct Negotiated {
    pub(crate) max_payload: u32,
    pub(crate) protocol_version: u32,
    pub(crate) config: ConnectionConfig,
    pub(crate) delayed_ack: bool,
    pub(crate) device_banner: DeviceBanner,
}

impl Negotiated {
    pub(crate) fn new(
        host_delayed_ack: bool,
        cnxn: Packet,
        config: ConnectionConfig,
    ) -> Result<Self, ProtocolError> {
        let device_banner = DeviceBanner::from_bytes(cnxn.data, config.max_banner_properties())?;
        let delayed_ack = host_delayed_ack && device_banner.has_feature(&Feature::DelayedAck);
        Ok(Self {
            max_payload: cnxn.arg1.min(command::MAX_PAYLOAD),
            protocol_version: cnxn.arg0.min(command::ADB_VERSION),
            config,
            delayed_ack,
            device_banner,
        })
    }

    pub(crate) fn ack_mode(&self) -> AckMode {
        if self.delayed_ack {
            AckMode::Delayed
        } else {
            AckMode::Classic
        }
    }

    pub(crate) fn rx_policy(&self) -> RxPolicy {
        RxPolicy {
            ack: self.ack_mode(),
            rx_cap: self.config.rx_cap(),
            watermark: self.config.rx_watermark(),
        }
    }

    pub(crate) fn checksum(&self) -> Checksum {
        Checksum::for_version(self.protocol_version)
    }

    pub(crate) fn advertised_credit(&self) -> Option<u32> {
        self.delayed_ack.then(|| self.config.advertised_ack_bytes())
    }

    pub(crate) fn advertises(&self, feature: &Feature) -> bool {
        self.device_banner.has_feature(feature)
    }

    pub(crate) fn require_feature<E>(&self, feature: Feature) -> Result<(), Error<E>> {
        if self.advertises(&feature) {
            Ok(())
        } else {
            Err(Error::MissingFeature(feature))
        }
    }
}
