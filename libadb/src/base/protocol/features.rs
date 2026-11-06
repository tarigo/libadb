//! [`Feature`], an entry of a CNXN banner's `features=` list, and the
//! ones this library advertises as a host.

use crate::error::ProtocolError;

macro_rules! features {
    ($($(#[$doc:meta])* $variant:ident => $wire:literal,)*) => {
        /// ADB feature flags supported by the device or host.
        ///
        /// Each variant corresponds to an individual feature string
        /// exchanged during the ADB `CNXN` handshake.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Feature {
            $($(#[$doc])* $variant,)*
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
    /// The `abb:` service, Android Binder Bridge over the shell protocol;
    /// see [`abb::open`](crate::abb::open).
    Abb => "abb",
    /// The `abb_exec:` service, Android Binder Bridge over a raw pipe; see
    /// [`abb::exec`](crate::abb::exec).
    AbbExec => "abb_exec",
    /// The device can install `.apex` packages.
    Apex => "apex",
    /// `track-app` entries say more about each process, such as its
    /// packages; see [`ProcessEntry`](crate::track_app::ProcessEntry).
    AppInfo => "app_info",
    /// The device has the `cmd` command, which the [`cmd`](crate::cmd) module runs.
    Cmd => "cmd",
    /// Delayed ACK: `WRTE`s in flight up to a byte credit per stream; on only
    /// if both sides list it ([`Connection::delayed_ack`](crate::Connection::delayed_ack)).
    DelayedAck => "delayed_ack",
    /// Named for the device tracker's protobuf output, which the ADB server
    /// gives as `host:track-devices-proto-binary`.
    DevicetrackerProtoFormat => "devicetracker_proto_format",
    /// The `dev-raw:<path>` service: a device file opened in raw tty mode.
    Devraw => "devraw",
    /// A push creates the directories its path lacks, which Android 9
    /// shipped broken (b/110953234); a side listing this has the fix.
    FixedPushMkdir => "fixed_push_mkdir",
    /// A push updates a symlink's timestamp properly.
    FixedPushSymlinkTimestamp => "fixed_push_symlink_timestamp",
    /// Sync's `LIS2` listing, each entry carrying what a `STA2` stat
    /// returns; see [`SyncSession::list_v2`](crate::sync::SyncSession::list_v2).
    LsV2 => "ls_v2",
    /// Named for mDNS discovery through Openscreen.
    OpenscreenMdns => "openscreen_mdns",
    /// `remount`, `enable-verity` and `disable-verity` run as shell
    /// commands rather than as the adbd services of those names.
    RemountShell => "remount_shell",
    /// Sync's `SND2` and `RCV2` transfers, which carry flags; see
    /// [`SyncSession::send_v2`](crate::sync::SyncSession::send_v2).
    SendrecvV2 => "sendrecv_v2",
    /// Brotli compression for `SND2` and `RCV2`; see
    /// [`SyncFlags::BROTLI`](crate::sync::SyncFlags::BROTLI).
    SendrecvV2Brotli => "sendrecv_v2_brotli",
    /// A dry-run `SND2`, which takes the data in but writes no file; see
    /// [`SyncFlags::DRY_RUN`](crate::sync::SyncFlags::DRY_RUN).
    SendrecvV2DryRunSend => "sendrecv_v2_dry_run_send",
    /// LZ4 compression for `SND2` and `RCV2`; see
    /// [`SyncFlags::LZ4`](crate::sync::SyncFlags::LZ4).
    SendrecvV2Lz4 => "sendrecv_v2_lz4",
    /// Zstandard compression for `SND2` and `RCV2`; see
    /// [`SyncFlags::ZSTD`](crate::sync::SyncFlags::ZSTD).
    SendrecvV2Zstd => "sendrecv_v2_zstd",
    /// The shell protocol, `shell,v2,…`: stdin, stdout and stderr framed
    /// apart, and the exit code; see [`shell::v2`](crate::shell::v2).
    ShellV2 => "shell_v2",
    /// Sync's `STA2` and `LST2` stats: 64-bit sizes and times, and an error
    /// code; see [`SyncSession::stat_v2`](crate::sync::SyncSession::stat_v2).
    StatV2 => "stat_v2",
    /// The `track-app` service, which reports debuggable and profileable
    /// apps; see [`track_app`](crate::track_app).
    TrackApp => "track_app",
}

/// Features this library actually implements on the wire and is safe
/// to advertise as a host to a device.
///
/// What [`HostBanner::default`](crate::HostBanner::default) advertises.
/// Compression variants of `sendrecv_v2` are intentionally excluded —
/// the library does not perform brotli/lz4/zstd itself, only the
/// uncompressed `SND2`/`RCV2` framing.
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
