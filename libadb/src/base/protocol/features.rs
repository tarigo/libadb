use super::super::error::ProtocolError;

macro_rules! features {
    ($($variant:ident => $wire:literal,)*) => {
        /// ADB feature flags supported by the device or host.
        ///
        /// Each variant corresponds to an individual feature string
        /// exchanged during the ADB `CNXN` handshake.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Feature {
            $($variant,)*
        }

        impl Feature {
            /// Canonical wire-format name as it appears inside the
            /// `features=` list of a CNXN banner (e.g. `"shell_v2"`).
            pub const fn wire_name(&self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)*
                }
            }
        }

        impl TryFrom<&str> for Feature {
            type Error = ProtocolError;
            fn try_from(text: &str) -> Result<Self, Self::Error> {
                match text {
                    $($wire => Ok(Self::$variant),)*
                    _ => Err(ProtocolError::UnknownFeature),
                }
            }
        }
    };
}

features! {
    Abb => "abb",
    AbbExec => "abb_exec",
    Apex => "apex",
    AppInfo => "app_info",
    Cmd => "cmd",
    DelayedAck => "delayed_ack",
    DevicetrackerProtoFormat => "devicetracker_proto_format",
    Devraw => "devraw",
    FixedPushMkdir => "fixed_push_mkdir",
    FixedPushSymlinkTimestamp => "fixed_push_symlink_timestamp",
    LsV2 => "ls_v2",
    OpenscreenMdns => "openscreen_mdns",
    RemountShell => "remount_shell",
    SendrecvV2 => "sendrecv_v2",
    SendrecvV2Brotli => "sendrecv_v2_brotli",
    SendrecvV2DryRunSend => "sendrecv_v2_dry_run_send",
    SendrecvV2Lz4 => "sendrecv_v2_lz4",
    SendrecvV2Zstd => "sendrecv_v2_zstd",
    ShellV2 => "shell_v2",
    StatV2 => "stat_v2",
    TrackApp => "track_app",
}

/// Features this library actually implements on the wire and is safe
/// to advertise as a host to a device.
///
/// Used by default when callers pass this slice to
/// [`Connection::connect`](crate::Connection::connect). Compression
/// variants of `sendrecv_v2` are intentionally excluded — the library
/// does not perform brotli/lz4/zstd itself, only the uncompressed
/// `SND2`/`RCV2` framing.
pub const DEFAULT_HOST_FEATURES: &[Feature] = &[
    Feature::ShellV2,
    Feature::Cmd,
    Feature::Abb,
    Feature::AbbExec,
    Feature::DelayedAck,
    Feature::TrackApp,
    Feature::AppInfo,
    Feature::StatV2,
    Feature::LsV2,
    Feature::SendrecvV2,
];

/// When delayed acks are supported, the initial number of unacknowledged bytes
/// we're willing to receive on a socket before the other side should block.
pub const INITIAL_DELAYED_ACK_BYTES: u32 = 32 * 1024 * 1024;

/// Feature name for delayed ACK support.
pub const DELAYED_ACK: &[u8] = b"delayed_ack";

/// Check whether a CNXN banner advertises a given feature.
///
/// Performs a simple byte-wise scan over the raw banner payload
/// (e.g. `host::features=shell_v2,delayed_ack`).
pub fn has_feature(banner: &[u8], feature: &[u8]) -> bool {
    let needle = b"features=";
    let Some(pos) = banner.windows(needle.len()).position(|w| w == needle) else {
        return false;
    };
    banner[pos + needle.len()..]
        .split(|b| *b == b',' || *b == b';')
        .any(|f| f == feature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_feature_detects_delayed_ack() {
        assert!(has_feature(
            b"host::features=shell_v2,delayed_ack",
            DELAYED_ACK
        ));
    }

    #[test]
    fn has_feature_rejects_unadvertised() {
        assert!(!has_feature(b"host::features=shell_v2,cmd", DELAYED_ACK));
    }

    #[test]
    fn has_feature_supports_single_entry() {
        assert!(has_feature(b"host::features=delayed_ack", DELAYED_ACK));
    }

    #[test]
    fn has_feature_returns_false_without_features_key() {
        assert!(!has_feature(b"host::", DELAYED_ACK));
    }

    #[test]
    fn has_feature_returns_false_on_empty_banner() {
        assert!(!has_feature(b"", DELAYED_ACK));
    }

    #[test]
    fn has_feature_rejects_substring_match() {
        assert!(!has_feature(b"host::features=delayed_ack_v2", DELAYED_ACK));
    }

    #[test]
    fn wire_name_roundtrips_via_try_from() {
        for f in DEFAULT_HOST_FEATURES {
            assert_eq!(Feature::try_from(f.wire_name()).unwrap(), *f);
        }
    }
}
