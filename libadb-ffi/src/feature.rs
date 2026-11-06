//! The `ADB_FEATURE_*` table and the C calls that ask a connection
//! about features.

use core::ffi::c_char;
use core::ptr;

use libadb::protocol::features::Feature;

use crate::connection::adb_connection_t;
use crate::error::{self, AdbStatus};

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

/// Whether the device advertises `feature`.
///
/// Returns `false` if `conn` is NULL, or if `feature` is not one of
/// the `ADB_FEATURE_*` constants defined in `libadb.h`.
///
/// # Safety
/// `conn` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_has_feature(
    conn: *const adb_connection_t,
    feature: u32,
) -> bool {
    if conn.is_null() {
        return false;
    }
    let Some(ff) = FfiFeature::from_raw(feature) else {
        return false;
    };
    // SAFETY: non-null, and a valid handle per `# Safety`.
    unsafe { &*conn }
        .writer
        .device_banner_parsed()
        .has_feature(&ff.to_feature())
}

/// Wire-format name of `feature` (e.g. `"shell_v2"`) as a static
/// NUL-terminated string, or NULL if `feature` is not one of the
/// `ADB_FEATURE_*` constants defined in `libadb.h`.
#[unsafe(no_mangle)]
pub extern "C" fn adb_feature_name(feature: u32) -> *const c_char {
    match FfiFeature::from_raw(feature) {
        Some(f) => f.wire_name(),
        None => ptr::null(),
    }
}

/// Copy up to `buf_cap` features advertised by the device into
/// `buf` (in handshake order) and write the full count through
/// `out_len`. Either pointer may be NULL; pass `(NULL, 0, &n)` to
/// query the count, then call again with a larger buffer.
///
/// Features the library does not recognise are skipped, so the count
/// covers only known `ADB_FEATURE_*` values.
///
/// # Safety
/// `conn` must be NULL or a valid handle. `buf` must be NULL or
/// point to at least `buf_cap` writable `uint32_t` slots.
/// `out_len` must be NULL or point to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_connection_features(
    conn: *const adb_connection_t,
    buf: *mut u32,
    buf_cap: usize,
    out_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let features = unsafe { &*conn }.writer.device_banner_parsed().features();
    if !out_len.is_null() {
        // SAFETY: non-null, so writable per `# Safety`.
        unsafe { *out_len = features.len() };
    }
    if !buf.is_null() && buf_cap > 0 {
        let n = features.len().min(buf_cap);
        for (slot, f) in features.iter().take(n).enumerate() {
            // SAFETY: `slot < n <= buf_cap`, and `buf` has `buf_cap` writable slots per `# Safety`.
            unsafe { *buf.add(slot) = FfiFeature::from_feature(f) as u32 };
        }
    }
    AdbStatus::Ok
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
            // SAFETY: `wire_name` points into a `'static` literal `features!` ends with a NUL.
            let name = unsafe { core::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
            let roundtrip = Feature::try_from(name).expect("wire name parses");
            assert_eq!(roundtrip, ff.to_feature());
        }
    }
}
