//! The ADB wire format: [`Packet`], the 24-byte [`message`] header it
//! travels under, the [`command`] and [`constant`] values, the
//! [`features`] a banner advertises, and the payload [`Checksum`].

mod checksum;
pub mod command;
pub mod constant;
pub mod features;
pub mod message;
mod packet;

pub use checksum::Checksum;
pub use command::Command;
pub(crate) use message::Message;
pub(crate) use message::MESSAGE_SIZE;
pub use packet::Packet;
