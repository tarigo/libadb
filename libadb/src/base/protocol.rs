mod checksum;
pub mod command;
pub mod constant;
pub mod features;
pub mod message;
mod packet;

// Only the types are public: their modules also hold implementation
// details — the payload sum, the header codec — that are not API.
pub use checksum::Checksum;
pub use command::Command;
pub(crate) use message::Message;
pub(crate) use message::MESSAGE_SIZE;
pub use packet::Packet;
