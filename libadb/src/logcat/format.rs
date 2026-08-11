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

/// Android log buffer identifier.
///
/// Matches the `log_id` values in AOSP
/// (`system/logging/liblog/include/android/log.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum LogId {
    Main = 0,
    Radio = 1,
    Events = 2,
    System = 3,
    Crash = 4,
    Stats = 5,
    Security = 6,
    Kernel = 7,
}

impl LogId {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Main,
            1 => Self::Radio,
            2 => Self::Events,
            3 => Self::System,
            4 => Self::Crash,
            5 => Self::Stats,
            6 => Self::Security,
            7 => Self::Kernel,
            _ => Self::Main,
        }
    }
}

impl fmt::Display for LogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Main => "main",
            Self::Radio => "radio",
            Self::Events => "events",
            Self::System => "system",
            Self::Crash => "crash",
            Self::Stats => "stats",
            Self::Security => "security",
            Self::Kernel => "kernel",
        })
    }
}

/// A parsed binary log entry.
///
/// Produced by [`Logcat::read_entry`](super::Logcat::read_entry).
///
/// For entries from the **events**, **stats** or **security** buffers
/// the payload uses a binary event format — [`tag`](Self::tag) will be
/// empty and [`message`](Self::message) will contain the entire raw
/// payload.  [`priority`](Self::priority) is not meaningful for those
/// buffers.
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
    /// Log tag.  Empty for events/stats/security buffers.
    pub tag: Vec<u8>,
    /// Log message body.  May or may not be valid UTF-8.
    /// For events/stats/security buffers this contains the entire raw
    /// binary payload.
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

/// Logcat binary-parsing error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogcatError {
    /// The `logger_entry` header has an `hdr_size` smaller than the
    /// minimum (24 bytes for v3).
    InvalidHeader,
}

impl fmt::Display for LogcatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader => f.write_str("logcat: invalid logger_entry header"),
        }
    }
}

impl core::error::Error for LogcatError {}

pub(super) const HEADER_V3_SIZE: usize = 24;
pub(super) const HEADER_V4_SIZE: usize = 28;

/// Try to parse one binary `logger_entry` from `buf`.
///
/// Returns `Ok(Some((entry, consumed)))` when a complete entry was
/// decoded, `Ok(None)` when the buffer does not yet contain enough
/// bytes, or `Err` on an unrecoverable format error.
///
/// This function is also usable standalone for parsing binary logcat
/// data obtained through other means (e.g. a file captured with
/// `logcat -B -f`).
pub(super) fn parse_entry(buf: &[u8]) -> Result<Option<(LogEntry, usize)>, LogcatError> {
    const HEADER_PREFIX: usize = 4;
    if buf.len() < HEADER_PREFIX {
        return Ok(None);
    }

    let payload_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let hdr_size = u16::from_le_bytes([buf[2], buf[3]]) as usize;

    if hdr_size < HEADER_V3_SIZE {
        return Err(LogcatError::InvalidHeader);
    }

    let total = hdr_size + payload_len;
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

    let log_id = LogId::from_u32(lid);

    let (priority, tag, message) = if payload.is_empty() {
        (Priority::Unknown, Vec::new(), Vec::new())
    } else if matches!(log_id, LogId::Events | LogId::Stats | LogId::Security) {
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
