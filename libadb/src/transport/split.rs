//! Splittable transports for full-duplex use.
//!
//! Implementors of [`Splittable`] can be broken into independent read and
//! write halves, which [`Connection::split`](crate::Connection::split) uses
//! to produce a [`Reader`](crate::Reader) / [`Writer`](crate::Writer) pair
//! that can be driven concurrently (from different threads or tasks).

use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};

/// Transport that can be broken into an owned read half and an owned
/// write half sharing the same underlying endpoint.
///
/// Both halves must report the same error type as the parent transport.
/// `split` is fallible to accommodate transports whose duplication can
/// fail at runtime (e.g. `TcpStream::try_clone`); most implementations
/// return `Ok` unconditionally.
pub trait Splittable: Read + Write + ErrorType {
    /// Owned half that reads from the endpoint.
    type ReadHalf: Read<Error = <Self as ErrorType>::Error>;
    /// Owned half that writes to the endpoint.
    type WriteHalf: Write<Error = <Self as ErrorType>::Error>;

    /// Consume the transport, returning independent read/write halves.
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), <Self as ErrorType>::Error>;
}
