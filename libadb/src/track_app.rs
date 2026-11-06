//! Track debuggable/profileable app processes on the device.
//!
//! Available on devices that advertise the `track_app` feature, this
//! opens a `track-app` channel and streams process snapshots as binary
//! protobuf messages.
//!
//! The device sends a full snapshot of all debuggable/profileable
//! processes immediately upon connection, then a new snapshot every
//! time the list changes (process starts, stops, or updates its
//! properties).
//!
//! Each wire message is framed as `[4 hex-ASCII length][protobuf payload]`.
//! The protobuf schema is `adb.proto.AppProcesses`:
//!
//! ```text
//! message ProcessEntry {
//!     int64  pid                    = 1;
//!     bool   debuggable             = 2;
//!     bool   profileable            = 3;
//!     string architecture           = 4;
//!     int64  user_id                = 5;  // optional
//!     string process_name           = 6;  // optional
//!     repeated string package_names = 7;
//!     bool   waiting_for_debugger   = 8;  // optional
//!     int64  uid                    = 9;  // optional
//! }
//!
//! message AppProcesses {
//!     repeated ProcessEntry process = 1;
//! }
//! ```
//!
//! # Examples
//!
//! ```ignore
//! let mut rx = [0u8; 8192];
//! let mut tracker = track_app::open(&mut conn, &mut rx).await?;
//!
//! loop {
//!     let snapshot = tracker.read_snapshot().await?;
//!     for proc in &snapshot {
//!         println!("pid={} name={:?} pkgs={:?}",
//!             proc.pid, proc.process_name, proc.package_names);
//!     }
//! }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::base::channel::Channel;
use crate::base::protobuf::{self as proto, DecodeError};
use crate::base::protocol::features::Feature;
use crate::base::recv_buf::RecvBuf;
use crate::base::session::Session;
use crate::error::Error;

/// A single process entry from the device.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessEntry {
    pub pid: i64,
    pub debuggable: bool,
    pub profileable: bool,
    pub architecture: String,
    pub user_id: Option<i64>,
    pub process_name: Option<String>,
    pub package_names: Vec<String>,
    pub waiting_for_debugger: Option<bool>,
    pub uid: Option<i64>,
}

/// A live `track-app` streaming session.
///
/// Wraps an ADB channel and a caller-owned receive buffer.  Call
/// [`read_snapshot`](Self::read_snapshot) in a loop to receive process
/// list updates.
pub struct TrackApp<'a, 'b, S> {
    channel: Channel<'a, S>,
    rx: RecvBuf<'b>,
}

impl<'a, 'b, S: Session> TrackApp<'a, 'b, S> {
    /// Wrap an already-opened `track-app` channel.
    ///
    /// `buf` is the caller-owned receive buffer. It must hold a snapshot
    /// and its 4-byte length prefix at once: a frame longer than `buf`
    /// fails [`read_snapshot`](Self::read_snapshot) with
    /// [`Error::ReceiveBufferFull`]. 8 KiB is a reasonable starting
    /// size — see [`open`].
    pub fn new(channel: Channel<'a, S>, buf: &'b mut [u8]) -> Self {
        Self {
            channel,
            rx: RecvBuf::new(buf),
        }
    }

    /// Read the next process-list snapshot from the device.
    ///
    /// Blocks until a complete `[4-hex-len][protobuf]` message has been
    /// received, then decodes and returns the list of processes.
    ///
    /// A snapshot that does not decode fails with [`Error::Decode`] and
    /// costs only itself: the next call reads the one after it. The
    /// stream cannot go past two other failures, and every later call
    /// fails the same: a frame longer than the buffer, with
    /// [`Error::ReceiveBufferFull`], and a length prefix that does not
    /// parse, with [`Error::Decode`].
    ///
    /// As safe to drop as the [`Channel`] read it waits in, which can
    /// lose packet bytes on a transport whose reads are not cancel-safe:
    /// see [`ReadCancelSafety`](crate::transport::ReadCancelSafety). The
    /// call itself loses nothing, as what arrived stays in the buffer
    /// for the next one.
    pub async fn read_snapshot(&mut self) -> Result<Vec<ProcessEntry>, Error<S::IoError>> {
        const HEX_LEN_PREFIX: usize = 4;
        self.rx
            .fill_at_least(&mut self.channel, HEX_LEN_PREFIX)
            .await?;
        let payload_len = proto::parse_hex4(self.rx.peek(HEX_LEN_PREFIX))
            .ok_or(Error::Decode(DecodeError::InvalidLengthPrefix))?
            as usize;
        // The prefix stays until the frame is in: a call dropped while
        // waiting must leave the next one in front of a prefix.
        let frame_len = HEX_LEN_PREFIX + payload_len;
        self.rx.fill_at_least(&mut self.channel, frame_len).await?;
        let entries = decode_app_processes(&self.rx.peek(frame_len)[HEX_LEN_PREFIX..]);
        self.rx.advance(frame_len);
        entries.map_err(Error::Decode)
    }

    /// Close the channel.
    pub async fn close(self) -> Result<(), Error<S::IoError>> {
        self.channel.close().await
    }
}

/// Open a `track-app` channel and return a [`TrackApp`] session.
///
/// `buf` is the caller-owned receive buffer, which must hold a snapshot
/// and its 4-byte length prefix at once.  8 KiB is a reasonable starting
/// size; increase if the device has many debuggable processes.
pub async fn open<'a, 'b, S: Session>(
    session: &'a mut S,
    buf: &'b mut [u8],
) -> Result<TrackApp<'a, 'b, S>, Error<S::IoError>> {
    session.require_feature(Feature::TrackApp)?;
    let channel = session.open(b"track-app\0").await?;
    Ok(TrackApp::new(channel, buf))
}

fn decode_app_processes(buf: &[u8]) -> Result<Vec<ProcessEntry>, DecodeError> {
    proto::decode_repeated_field1(buf, decode_process_entry)
}

fn decode_process_entry(buf: &[u8]) -> Result<ProcessEntry, DecodeError> {
    let mut entry = ProcessEntry::default();
    let mut pos = 0;

    while pos < buf.len() {
        let (field, wire, c) = proto::read_tag(&buf[pos..])?;
        pos += c;

        match (field, wire) {
            (1, 0) => {
                let (v, c) = proto::read_varint(&buf[pos..])?;
                pos += c;
                entry.pid = v as i64;
            }
            (2, 0) => {
                let (v, c) = proto::read_varint(&buf[pos..])?;
                pos += c;
                entry.debuggable = v != 0;
            }
            (3, 0) => {
                let (v, c) = proto::read_varint(&buf[pos..])?;
                pos += c;
                entry.profileable = v != 0;
            }
            (4, 2) => {
                let (s, c) = proto::read_string(&buf[pos..])?;
                pos += c;
                entry.architecture = s;
            }
            (5, 0) => {
                let (v, c) = proto::read_varint(&buf[pos..])?;
                pos += c;
                entry.user_id = Some(v as i64);
            }
            (6, 2) => {
                let (s, c) = proto::read_string(&buf[pos..])?;
                pos += c;
                entry.process_name = Some(s);
            }
            (7, 2) => {
                let (s, c) = proto::read_string(&buf[pos..])?;
                pos += c;
                entry.package_names.push(s);
            }
            (8, 0) => {
                let (v, c) = proto::read_varint(&buf[pos..])?;
                pos += c;
                entry.waiting_for_debugger = Some(v != 0);
            }
            (9, 0) => {
                let (v, c) = proto::read_varint(&buf[pos..])?;
                pos += c;
                entry.uid = Some(v as i64);
            }
            _ => {
                pos += proto::skip_field(&buf[pos..], wire).ok_or(DecodeError::InvalidProtobuf)?;
            }
        }
    }

    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::mock::{abandon, now, one_slot, wrte};
    use alloc::format;
    use alloc::vec;

    const FIELD_PID: u64 = 1;
    const FIELD_DEBUGGABLE: u64 = 2;
    const FIELD_ARCHITECTURE: u64 = 4;
    const FIELD_PROCESS_NAME: u64 = 6;
    const FIELD_PACKAGE_NAMES: u64 = 7;
    const FIELD_PROCESS_ENTRY: u64 = 1;

    const WIRE_VARINT: u64 = 0;
    const WIRE_LEN_DELIMITED: u64 = 2;

    fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            buf.push((value as u8) | 0x80);
            value >>= 7;
        }
        buf.push(value as u8);
    }

    fn write_tag(buf: &mut Vec<u8>, field: u64, wire: u64) {
        write_varint(buf, (field << 3) | wire);
    }

    fn write_varint_field(buf: &mut Vec<u8>, field: u64, value: u64) {
        write_tag(buf, field, WIRE_VARINT);
        write_varint(buf, value);
    }

    fn write_bool_field(buf: &mut Vec<u8>, field: u64, value: bool) {
        write_varint_field(buf, field, value as u64);
    }

    fn write_string_field(buf: &mut Vec<u8>, field: u64, value: &[u8]) {
        write_tag(buf, field, WIRE_LEN_DELIMITED);
        write_varint(buf, value.len() as u64);
        buf.extend_from_slice(value);
    }

    fn wrap_as_app_processes(entry: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        write_string_field(&mut msg, FIELD_PROCESS_ENTRY, entry);
        msg
    }

    /// A frame as the device writes it.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len()).into_bytes();
        out.extend_from_slice(payload);
        out
    }

    /// The frame of a snapshot listing one process.
    fn snapshot(pid: u64) -> Vec<u8> {
        let mut entry = Vec::new();
        write_varint_field(&mut entry, FIELD_PID, pid);
        frame(&wrap_as_app_processes(&entry))
    }

    fn pids(entries: &[ProcessEntry]) -> Vec<i64> {
        entries.iter().map(|e| e.pid).collect()
    }

    #[test]
    fn a_snapshot_that_fails_to_decode_costs_only_that_snapshot() {
        // Field 1 claims more bytes than the message holds.
        let mut stream = frame(&[0x0A, 0x7F]);
        stream.extend(snapshot(7));
        let mut conn = one_slot("track_app", &[wrte(1, &stream)]);
        let mut rx = [0u8; 256];
        let mut tracker = now(open(&mut conn, &mut rx)).unwrap();

        let err = now(tracker.read_snapshot()).unwrap_err();
        assert!(
            matches!(err, Error::Decode(DecodeError::InvalidProtobuf)),
            "got {err:?}"
        );
        assert_eq!(pids(&now(tracker.read_snapshot()).unwrap()), [7]);
    }

    #[test]
    fn a_call_dropped_anywhere_in_a_frame_costs_nothing() {
        let stream = snapshot(7);
        for cut in 0..stream.len() {
            let mut conn = one_slot("track_app", &[]);
            let mut rx = [0u8; 256];
            let mut tracker = now(open(&mut conn, &mut rx)).unwrap();
            let device = tracker.channel.session.transport_mut();
            device.parks_when_drained();
            if cut > 0 {
                device.feed(&wrte(1, &stream[..cut]));
            }

            abandon(tracker.read_snapshot());

            let device = tracker.channel.session.transport_mut();
            device.feed(&wrte(1, &stream[cut..]));
            let entries = now(tracker.read_snapshot()).unwrap();
            assert_eq!(pids(&entries), [7], "dropped {cut} bytes in");
        }
    }

    #[test]
    fn a_frame_fits_a_buffer_of_exactly_its_length() {
        let stream = snapshot(7);
        let mut conn = one_slot("track_app", &[wrte(1, &stream)]);
        let mut rx = vec![0u8; stream.len()];
        let mut tracker = now(open(&mut conn, &mut rx)).unwrap();

        assert_eq!(pids(&now(tracker.read_snapshot()).unwrap()), [7]);
    }

    #[test]
    fn a_frame_a_byte_too_long_for_the_buffer_fails_every_call() {
        let stream = snapshot(7);
        let mut conn = one_slot("track_app", &[wrte(1, &stream)]);
        let mut rx = vec![0u8; stream.len() - 1];
        let mut tracker = now(open(&mut conn, &mut rx)).unwrap();

        for _ in 0..2 {
            let err = now(tracker.read_snapshot()).unwrap_err();
            assert!(matches!(err, Error::ReceiveBufferFull), "got {err:?}");
        }
    }

    #[test]
    fn a_prefix_that_does_not_parse_fails_every_call() {
        let mut conn = one_slot("track_app", &[wrte(1, b"ZZZZ")]);
        let mut rx = [0u8; 256];
        let mut tracker = now(open(&mut conn, &mut rx)).unwrap();

        for _ in 0..2 {
            let err = now(tracker.read_snapshot()).unwrap_err();
            assert!(
                matches!(err, Error::Decode(DecodeError::InvalidLengthPrefix)),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn decode_empty_app_processes() {
        let entries = decode_app_processes(&[]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn decode_single_process_entry() {
        let mut entry = Vec::new();
        write_varint_field(&mut entry, FIELD_PID, 1234);
        write_bool_field(&mut entry, FIELD_DEBUGGABLE, true);
        write_string_field(&mut entry, FIELD_ARCHITECTURE, b"arm64");
        write_string_field(&mut entry, FIELD_PROCESS_NAME, b"com.example.app");

        let entries = decode_app_processes(&wrap_as_app_processes(&entry)).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.pid, 1234);
        assert!(e.debuggable);
        assert!(!e.profileable);
        assert_eq!(e.architecture, "arm64");
        assert_eq!(e.process_name.as_deref(), Some("com.example.app"));
        assert!(e.package_names.is_empty());
    }

    #[test]
    fn decode_process_with_packages() {
        let mut entry = Vec::new();
        write_varint_field(&mut entry, FIELD_PID, 42);
        write_string_field(&mut entry, FIELD_PACKAGE_NAMES, b"com.foo");
        write_string_field(&mut entry, FIELD_PACKAGE_NAMES, b"com.bar");

        let entries = decode_app_processes(&wrap_as_app_processes(&entry)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package_names, vec!["com.foo", "com.bar"]);
    }
}
