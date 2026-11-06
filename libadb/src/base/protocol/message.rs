//! [`Message`], the 24-byte header every packet starts with.

/// Size of the ADB message in bytes.
pub const MESSAGE_SIZE: usize = 24;

/// ADB message (24 bytes, little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    /// The command identifier, such as [`CMD_CNXN`](super::command::CMD_CNXN).
    pub command: u32,
    /// First argument; meaning depends on `command`.
    pub arg0: u32,
    /// Second argument; meaning depends on `command`.
    pub arg1: u32,
    /// Length of the payload that follows, in bytes; 0 is allowed.
    pub data_length: u32,
    /// The payload's byte sum, or 0 where [`Checksum`](super::Checksum)
    /// skips it.
    pub data_check: u32,
    /// `command ^ 0xFFFF_FFFF`.
    pub magic: u32,
}
