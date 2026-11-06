use alloc::vec::Vec;
use bytes::Bytes;

use crate::base::protocol::features::{Feature, DEFAULT_HOST_FEATURES};

/// The identity banner the host sends in its CNXN.
///
/// It names the features this host speaks. Delayed ACK (credit-based
/// flow control) is on only when the banner names it and the device's
/// banner does too.
///
/// Most callers name features and let the banner be built from them;
/// [`Raw`](Self::Raw) is for a banner that carries more than a feature
/// list. [`HostBanner::default()`] advertises
/// [`DEFAULT_HOST_FEATURES`], everything this library implements.
///
/// ```
/// use libadb::{Feature, HostBanner};
///
/// // Sends `host::features=shell_v2,delayed_ack`.
/// let built = HostBanner::Features(&[Feature::ShellV2, Feature::DelayedAck]);
/// // Sends the same bytes, spelled out.
/// let raw = HostBanner::Raw(b"host::features=shell_v2,delayed_ack");
/// # let _ = (built, raw);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostBanner<'a> {
    /// `host::features=<csv>` built from these features, in order.
    Features(&'a [Feature]),
    /// Sent as given, e.g. `b"host::features=shell_v2,delayed_ack"`.
    ///
    /// Delayed ACK is negotiated from these bytes as from a built
    /// banner: it is on when they name `delayed_ack` among their
    /// features and the device does too.
    Raw(&'a [u8]),
}

/// [`HostBanner::Features`] of [`DEFAULT_HOST_FEATURES`]: everything
/// this library implements on the wire.
impl Default for HostBanner<'_> {
    fn default() -> Self {
        Self::Features(DEFAULT_HOST_FEATURES)
    }
}

impl HostBanner<'_> {
    pub(crate) fn to_bytes(self) -> Bytes {
        match self {
            Self::Features(features) => {
                let mut banner = Vec::from(&b"host::features="[..]);
                for (i, f) in features.iter().enumerate() {
                    if i > 0 {
                        banner.push(b',');
                    }
                    banner.extend_from_slice(f.wire_name().as_bytes());
                }
                banner.into()
            }
            Self::Raw(raw) => Bytes::copy_from_slice(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::protocol::features;

    #[test]
    fn no_features_build_an_empty_list() {
        assert_eq!(
            HostBanner::Features(&[]).to_bytes(),
            &b"host::features="[..]
        );
    }

    #[test]
    fn a_single_feature_stands_alone() {
        assert_eq!(
            HostBanner::Features(&[Feature::ShellV2]).to_bytes(),
            &b"host::features=shell_v2"[..],
        );
    }

    #[test]
    fn features_keep_their_order() {
        assert_eq!(
            HostBanner::Features(&[Feature::ShellV2, Feature::Cmd, Feature::DelayedAck]).to_bytes(),
            &b"host::features=shell_v2,cmd,delayed_ack"[..],
        );
    }

    #[test]
    fn a_raw_banner_goes_out_as_given() {
        let raw = b"host::ro.product.name=x;features=shell_v2";
        assert_eq!(HostBanner::Raw(raw).to_bytes(), &raw[..]);
    }

    #[test]
    fn the_default_advertises_every_default_feature() {
        assert_eq!(
            HostBanner::default(),
            HostBanner::Features(DEFAULT_HOST_FEATURES)
        );
        let banner = HostBanner::default().to_bytes();
        assert!(banner.starts_with(b"host::features="));
        for f in DEFAULT_HOST_FEATURES {
            assert!(
                features::has_feature(&banner, f.wire_name().as_bytes()),
                "banner does not advertise {f:?}",
            );
        }
    }
}
