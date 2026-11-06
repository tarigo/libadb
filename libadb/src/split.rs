//! Full-duplex Reader/Writer pair for a Connection whose transport is
//! [`Splittable`](crate::Splittable).
//!
//! `Reader` owns the read half and drives packet reception; `Writer`
//! owns a cheap handle to the shared write-half + channel table and can
//! be cloned for use from other threads/tasks. Read-path and write-path
//! never hold the same mutex concurrently, so a thread blocked in
//! [`Reader::read_channel`] does not prevent another thread from calling
//! [`Writer::write_channel`] or [`Writer::close_channel`].
//!
//! # Driving the connection
//!
//! There are two ways to use the pair:
//!
//! * **Reader-driven.** One task keeps the `Reader` and calls
//!   [`Reader::open_channel`] and [`Reader::read_channel`] itself;
//!   writers send from anywhere. Packets for other channels are
//!   buffered while it waits, but only that task can collect them. A
//!   writer parked for credit moves only once something reads, so with
//!   no read under way the task takes packets one at a time with
//!   [`Reader::dispatch_one`]; [`Writer::waits_for_credit`] says when.
//! * **Dispatched.** [`Reader::run`] takes the `Reader` and does
//!   nothing but receive and dispatch packets, waking whoever waits on
//!   the channel each one is for. Every channel operation then goes
//!   through the `Writer` — [`Writer::open_channel`],
//!   [`Writer::read_channel`], [`Writer::write_channel`],
//!   [`Writer::close_channel`] — so any number of tasks can work on
//!   their own channels at once and none waits on another's traffic.
//!   Channels the device opens (`adb reverse`) are taken through an
//!   [`IncomingListener`] from [`Writer::listen_incoming`].
//!
//! Once the connection has ended — `run` returned, the `Reader` was
//! dropped, or a receive failed for good on a reader-driven connection
//! — every `Writer` call that waits on the device fails with
//! [`Error::Disconnected`] instead of waiting for packets nobody reads:
//! opening a channel, reading one, waiting for send credit, accepting
//! one the device opened. Calls that need no answer — a write the
//! credit already covers, a close — still reach the transport, with one
//! exception: a close on a stream that has ended frees its slot without
//! a CLSE. A read timeout is no such failure: it is the caller's to
//! handle, and leaves the connection and everyone waiting on it as they
//! were.
//!
//! What arrived stays readable however the connection fails: a read
//! hands over what its channel has buffered first, and only then fails
//! with [`Error::Disconnected`] or [`Error::Desynchronized`]. Every
//! other call on a desynchronized connection fails at once.
//!
//! Available under the `split` feature (implied by every runtime
//! feature: `tokio`, `smol`, `nusb`, `rusb`). Pulls `std` into the
//! build for its sync primitives; a pure `no_std` variant would need a
//! no_std Mutex implementation and is not yet provided.
//!
//! # Close ↔ read coordination
//!
//! Because only the `Reader` drives packet reception, calling
//! [`Writer::close_channel`] does not by itself wake a concurrent
//! [`Reader::read_channel`] parked on the same channel: the reader
//! unblocks only once it receives the device's echoed `CLSE` packet.
//! If the device is slow or non-conformant and never echoes the close,
//! an in-flight `read_channel` can remain blocked until the transport
//! itself fails. Drop the `Reader` (or fail the transport) to unblock
//! such a reader unconditionally.

mod accept;
mod reader;
mod shared;
#[cfg(test)]
mod tests;
mod writer;

pub use accept::{IncomingListener, SplitIncoming};
pub use reader::Reader;
pub(crate) use shared::Shared;
pub use writer::Writer;

#[cfg(doc)]
use crate::error::Error;
