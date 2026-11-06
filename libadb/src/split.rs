//! Full-duplex Reader/Writer pair for a Connection whose transport is
//! [`Splittable`](crate::Splittable).
//!
//! `Reader` owns the read half and drives packet reception. `Writer` is
//! a cheap handle to the shared write half and channel table, and can
//! be cloned for use from other threads and tasks. A thread blocked in
//! [`Reader::read_channel`] does not prevent another thread from
//! calling [`Writer::write_channel`] or [`Writer::close_channel`].
//!
//! Available under the `split` feature (implied by every runtime
//! feature: `tokio`, `smol`, `nusb`, `rusb`). Pulls `std` into the
//! build for its sync primitives; a pure `no_std` variant would need a
//! no_std Mutex implementation and is not yet provided.
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
//! # When the connection ends
//!
//! The connection has ended once `run` returned, the `Reader` was
//! dropped, or a receive failed for good on a reader-driven connection.
//! Every `Writer` call that waits on the device then fails with
//! [`Error::Disconnected`] instead of waiting for packets nobody reads:
//! opening a channel, reading one, waiting for send credit, accepting
//! one the device opened. Calls that need no answer, a write the credit
//! already covers or a close, still reach the transport, except that a
//! close on a stream that has ended frees its slot without a CLSE.
//!
//! A read timeout is no such failure: it is the caller's to handle, and
//! leaves the connection and everyone waiting on it as they were.
//!
//! # What arrived stays readable
//!
//! However the connection fails, a read first hands over what its
//! channel has buffered, and only then fails with
//! [`Error::Disconnected`] or [`Error::Desynchronized`]. Every other
//! call on a desynchronized connection fails at once.
//!
//! A read does not depend on its OKAY. One that fails does not fail the
//! read: the next call reports the failure. Once the connection has
//! ended, or a write was abandoned mid-packet, a read sends no OKAY and
//! does not wait for the write half, and a read already waiting to send
//! one stops. The bytes then come without their OKAY, so a stalled
//! writer or transport cannot keep them back.
//!
//! # What the device is owed
//!
//! The OKAY for data that arrived and the CLSE for a channel closed
//! here are recorded before any wait. The next write, open, close or
//! receive sends them before anything else, so a call dropped while it
//! waits for the write half loses neither. Once the connection has
//! ended a receive no longer sends them. While anything is owed nothing
//! is received, on any channel: a close behind a stalled writer holds
//! up reception until the write half comes free.
//!
//! No CLSE is sent to a device that is gone. Once a write found it gone
//! or a receive found the stream over, [`Writer::close_channel`]
//! returns `Ok` without one, and a close already waiting gives up if a
//! read still under way finds the stream over. A dropped `Reader` is
//! different: the device can still hear the CLSE, and a close waits for
//! the write half as usual.
//!
//! # Dropping a call
//!
//! Each call says whether it is safe to drop. Waiting for the write
//! half always is. Two other waits are not:
//!
//! * **Writing a packet.** From the moment a packet's write is first
//!   polled, a drop abandons the packet and desynchronizes the
//!   connection: see [`Error::Desynchronized`]. Every call on the
//!   `Reader` and on any `Writer` then fails with that error, calls
//!   already waiting included, and reads once they have handed over
//!   what had already arrived. Close the connection and open a new one.
//! * **Reading a packet.** A call on the `Reader` waits for a packet in
//!   a transport read. Where reads are not cancel-safe (USB), dropping
//!   it can lose packet bytes: see
//!   [`ReadCancelSafety`](crate::transport::ReadCancelSafety).
//!
//! # Closing while a read waits
//!
//! Only the `Reader` drives packet reception, so
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
