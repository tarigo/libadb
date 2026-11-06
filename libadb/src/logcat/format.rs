use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Log priority level.
///
/// Matches the `android_LogPriority` enum in AOSP
/// (`system/logging/liblog/include/android/log.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Priority {
    Unknown = 0,
    Default = 1,
    Verbose = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
    Fatal = 7,
    Silent = 8,
}

impl Priority {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => Self::Unknown,
            1 => Self::Default,
            2 => Self::Verbose,
            3 => Self::Debug,
            4 => Self::Info,
            5 => Self::Warn,
            6 => Self::Error,
            7 => Self::Fatal,
            8 => Self::Silent,
            _ => Self::Unknown,
        }
    }

    /// Single-character abbreviation used by the text logcat format.
    pub fn as_char(self) -> char {
        match self {
            Self::Unknown | Self::Default => '?',
            Self::Verbose => 'V',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warn => 'W',
            Self::Error => 'E',
            Self::Fatal => 'F',
            Self::Silent => 'S',
        }
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "UNKNOWN",
            Self::Default => "DEFAULT",
            Self::Verbose => "VERBOSE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
            Self::Silent => "SILENT",
        })
    }
}

/// Defines [`LogId`] from one row per known buffer, so the enum and
/// every conversion take a buffer's number, name and format from there.
macro_rules! log_ids {
    (@text text) => { true };
    (@text binary) => { false };
    (
        $(#[$attr:meta])*
        pub enum LogId {
            $($variant:ident = $number:literal, $name:literal, $format:ident;)*
            $(#[$unknown_attr:meta])*
            Unknown(UnknownLogId),
        }
    ) => {
        $(#[$attr])*
        pub enum LogId {
            $(
                #[doc = concat!("Buffer ", stringify!($number), ", `", $name, "`.")]
                $variant,
            )*
            $(#[$unknown_attr])*
            Unknown(UnknownLogId),
        }

        impl LogId {
            /// Whether this buffer's entries are `[priority][tag\0][message]`
            /// text.
            fn is_text(self) -> bool {
                match self {
                    $(Self::$variant => log_ids!(@text $format),)*
                    Self::Unknown(_) => false,
                }
            }
        }

        impl From<u32> for LogId {
            fn from(number: u32) -> Self {
                match number {
                    $($number => Self::$variant,)*
                    _ => Self::Unknown(UnknownLogId(number)),
                }
            }
        }

        impl From<LogId> for u32 {
            fn from(id: LogId) -> Self {
                match id {
                    $(LogId::$variant => $number,)*
                    LogId::Unknown(UnknownLogId(other)) => other,
                }
            }
        }

        impl fmt::Display for LogId {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant => f.write_str($name),)*
                    Self::Unknown(UnknownLogId(other)) => write!(f, "unknown({other})"),
                }
            }
        }
    };
}

log_ids! {
    /// Android log buffer identifier.
    ///
    /// Matches the `log_id` values in AOSP
    /// (`system/logging/liblog/include/android/log.h`) as of Android 9.
    /// Android 7.0–8.1 had no stats buffer and numbered security 5 and
    /// kernel 6, so from those releases security entries come out as
    /// [`Stats`](Self::Stats) and kernel entries as
    /// [`Security`](Self::Security), with their payload left raw.
    ///
    /// `LogId::from` turns a buffer number into its id, and `u32::from`
    /// gives the number back.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum LogId {
        Main = 0, "main", text;
        Radio = 1, "radio", text;
        Events = 2, "events", binary;
        System = 3, "system", text;
        Crash = 4, "crash", text;
        Stats = 5, "stats", binary;
        Security = 6, "security", binary;
        Kernel = 7, "kernel", text;
        /// A buffer this version of libadb does not know, such as one a
        /// newer Android added. Compare `u32::from(id)` rather than this
        /// variant: a later libadb may name the buffer.
        ///
        /// ```
        /// use libadb::logcat::LogId;
        ///
        /// let id = LogId::from(8);
        /// assert!(matches!(id, LogId::Unknown(_)));
        /// assert_eq!(u32::from(id), 8);
        /// ```
        ///
        /// The number inside is private, so a known number cannot pose as an
        /// unknown buffer, and no pattern can pick out one unknown number:
        ///
        /// ```compile_fail,E0423
        /// use libadb::logcat::{LogId, UnknownLogId};
        ///
        /// let system = LogId::Unknown(UnknownLogId(3));
        /// ```
        Unknown(UnknownLogId),
    }
}

/// The number of a buffer behind [`LogId::Unknown`], kept private.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownLogId(u32);

/// A parsed binary log entry.
///
/// Produced by [`Logcat::read_entry`](super::Logcat::read_entry).
///
/// For entries from the **events**, **stats** or **security** buffers
/// the payload uses a binary event format — [`tag`](Self::tag) will be
/// empty and [`message`](Self::message) will contain the entire raw
/// payload.  [`priority`](Self::priority) is not meaningful for those
/// buffers.  An entry from a buffer libadb does not know,
/// [`LogId::Unknown`], is left raw the same way, since its format is
/// unknown too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Process ID that generated the entry.
    pub pid: u32,
    /// Thread ID that generated the entry.
    pub tid: u32,
    /// Timestamp — seconds since Unix epoch.
    pub sec: u32,
    /// Timestamp — nanoseconds component.
    pub nsec: u32,
    /// UID of the generating process (0 if the header predates v4).
    pub uid: u32,
    /// Log buffer this entry was read from.
    pub log_id: LogId,
    /// Log priority (meaningful for main/system/radio/crash/kernel).
    pub priority: Priority,
    /// Log tag.  Empty for events/stats/security buffers and those
    /// libadb does not know.
    pub tag: Vec<u8>,
    /// Log message body.  May or may not be valid UTF-8.
    /// For events/stats/security buffers and those libadb does not know
    /// this contains the entire raw payload.
    pub message: Vec<u8>,
}

impl LogEntry {
    /// Tag as a UTF-8 string, replacing invalid sequences.
    pub fn tag_lossy(&self) -> alloc::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.tag)
    }

    /// Message as a UTF-8 string, replacing invalid sequences.
    pub fn message_lossy(&self) -> alloc::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.message)
    }
}

/// Why a logcat session failed: its output did not parse or was cut
/// short, or logcat itself failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogcatError {
    /// The `logger_entry` header has an `hdr_size` smaller than the
    /// minimum (24 bytes for v3), or adds up to an entry longer than
    /// the 5 KiB logcat ever writes. Text output, such as `-g` prints,
    /// fails this way.
    InvalidHeader,
    /// logcat exited with a non-zero status, as it does on an unknown
    /// buffer or option, or when it falls behind the log. A signal that
    /// ended it shows as 0x80 plus the signal number.
    Exited {
        /// logcat's exit status.
        code: u8,
        /// What logcat wrote to stderr, up to its first 1 KiB. The error's
        /// `Display` shows only the line that gives the reason, the first
        /// that is not a warning, and leaves out what follows it, such as
        /// the usage text older logcat prints.
        stderr: Vec<u8>,
    },
    /// The channel closed before logcat's exit status arrived, so its
    /// output may have been cut short.
    ClosedWithoutExit,
    /// logcat exited with status 0 in the middle of an entry, so the
    /// rest of that entry never came.
    TruncatedEntry,
}

impl fmt::Display for LogcatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader => f.write_str("logcat: invalid logger_entry header"),
            Self::Exited { code, stderr } => {
                write!(f, "logcat exited with status {code}")?;
                let said = String::from_utf8_lossy(stderr);
                let reason = said
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty() && !line.starts_with("WARNING:"));
                match reason {
                    Some(reason) => write!(f, ": {reason}"),
                    None => Ok(()),
                }
            }
            Self::ClosedWithoutExit => {
                f.write_str("logcat's channel closed before its exit status arrived")
            }
            Self::TruncatedEntry => f.write_str("logcat's output ended in the middle of an entry"),
        }
    }
}

impl core::error::Error for LogcatError {}

pub(super) const HEADER_V3_SIZE: usize = 24;
pub(super) const HEADER_V4_SIZE: usize = 28;
pub(super) const LOGGER_ENTRY_MAX_LEN: usize = 5 * 1024;

/// Try to parse one binary `logger_entry` from `buf`: `Ok(None)` until
/// it holds a whole entry, `Err` on an unrecoverable format error.
pub(super) fn parse_entry(buf: &[u8]) -> Result<Option<(LogEntry, usize)>, LogcatError> {
    const HEADER_PREFIX: usize = 4;
    if buf.len() < HEADER_PREFIX {
        return Ok(None);
    }

    let payload_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let hdr_size = u16::from_le_bytes([buf[2], buf[3]]) as usize;

    let total = hdr_size + payload_len;
    if hdr_size < HEADER_V3_SIZE || total > LOGGER_ENTRY_MAX_LEN {
        return Err(LogcatError::InvalidHeader);
    }
    if buf.len() < total {
        return Ok(None);
    }

    let pid = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u32;
    let tid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let sec = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as u32;
    let nsec = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]) as u32;
    let lid = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
    let uid = if hdr_size >= HEADER_V4_SIZE {
        u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]])
    } else {
        0
    };

    let payload = &buf[hdr_size..total];

    let log_id = LogId::from(lid);

    let (priority, tag, message) = if payload.is_empty() {
        (Priority::Unknown, Vec::new(), Vec::new())
    } else if !log_id.is_text() {
        (Priority::Unknown, Vec::new(), payload.to_vec())
    } else {
        let priority = Priority::from_u8(payload[0]);
        let rest = &payload[1..];

        let tag_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let tag = rest[..tag_end].to_vec();

        let msg_start = (tag_end + 1).min(rest.len());
        let mut message = rest[msg_start..].to_vec();
        if message.last() == Some(&0) {
            message.pop();
        }

        (priority, tag, message)
    };

    Ok(Some((
        LogEntry {
            pid,
            tid,
            sec,
            nsec,
            uid,
            log_id,
            priority,
            tag,
            message,
        },
        total,
    )))
}
