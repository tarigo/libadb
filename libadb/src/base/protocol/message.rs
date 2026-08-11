/// Size of the ADB message in bytes.
pub const MESSAGE_SIZE: usize = 24;

/// ADB message (24 bytes, little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_check: u32,
    pub magic: u32,
}
