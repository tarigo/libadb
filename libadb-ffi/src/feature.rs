use core::ffi::c_char;

use libadb::protocol::features::Feature;

macro_rules! features {
    ($($variant:ident = $discriminant:literal => $rust:ident, $wire:literal;)*) => {
        #[repr(u32)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum FfiFeature {
            $($variant = $discriminant,)*
        }

        impl FfiFeature {
            pub(crate) fn from_raw(value: u32) -> Option<Self> {
                Some(match value {
                    $($discriminant => Self::$variant,)*
                    _ => return None,
                })
            }

            pub(crate) fn to_feature(self) -> Feature {
                match self {
                    $(Self::$variant => Feature::$rust,)*
                }
            }

            pub(crate) fn from_feature(feature: &Feature) -> Self {
                match feature {
                    $(Feature::$rust => Self::$variant,)*
                }
            }

            pub(crate) fn wire_name(self) -> *const c_char {
                match self {
                    $(Self::$variant => concat!($wire, "\0").as_ptr().cast::<c_char>(),)*
                }
            }
        }
    };
}

features! {
    Abb = 0 => Abb, "abb";
    AbbExec = 1 => AbbExec, "abb_exec";
    Apex = 2 => Apex, "apex";
    AppInfo = 3 => AppInfo, "app_info";
    Cmd = 4 => Cmd, "cmd";
    DelayedAck = 5 => DelayedAck, "delayed_ack";
    DevicetrackerProtoFormat = 6 => DevicetrackerProtoFormat, "devicetracker_proto_format";
    Devraw = 7 => Devraw, "devraw";
    FixedPushMkdir = 8 => FixedPushMkdir, "fixed_push_mkdir";
    FixedPushSymlinkTimestamp = 9 => FixedPushSymlinkTimestamp, "fixed_push_symlink_timestamp";
    LsV2 = 10 => LsV2, "ls_v2";
    OpenscreenMdns = 11 => OpenscreenMdns, "openscreen_mdns";
    RemountShell = 12 => RemountShell, "remount_shell";
    SendrecvV2 = 13 => SendrecvV2, "sendrecv_v2";
    SendrecvV2Brotli = 14 => SendrecvV2Brotli, "sendrecv_v2_brotli";
    SendrecvV2DryRunSend = 15 => SendrecvV2DryRunSend, "sendrecv_v2_dry_run_send";
    SendrecvV2Lz4 = 16 => SendrecvV2Lz4, "sendrecv_v2_lz4";
    SendrecvV2Zstd = 17 => SendrecvV2Zstd, "sendrecv_v2_zstd";
    ShellV2 = 18 => ShellV2, "shell_v2";
    StatV2 = 19 => StatV2, "stat_v2";
    TrackApp = 20 => TrackApp, "track_app";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_roundtrips_through_to_feature() {
        for raw in 0u32..=20 {
            let ff = FfiFeature::from_raw(raw).expect("known discriminant");
            let feature = ff.to_feature();
            assert_eq!(FfiFeature::from_feature(&feature), ff);
            assert_eq!(FfiFeature::from_feature(&feature) as u32, raw);
        }
    }

    #[test]
    fn from_raw_rejects_unknown_values() {
        assert!(FfiFeature::from_raw(21).is_none());
        assert!(FfiFeature::from_raw(u32::MAX).is_none());
    }

    #[test]
    fn wire_name_matches_feature_try_from_str() {
        for raw in 0u32..=20 {
            let ff = FfiFeature::from_raw(raw).unwrap();
            let ptr = ff.wire_name();
            assert!(!ptr.is_null());
            // SAFETY: `wire_name()` returns a `&'static c_char` pointer
            // into a statically built nul-terminated literal table (see
            // the `c"..."` strings in `ffi_feature_enum!`).
            let name = unsafe { core::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
            let roundtrip = Feature::try_from(name).expect("wire name parses");
            assert_eq!(roundtrip, ff.to_feature());
        }
    }
}
