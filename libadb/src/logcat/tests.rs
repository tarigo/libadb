extern crate std;

use super::format::{HEADER_V3_SIZE, HEADER_V4_SIZE};
use super::*;
use alloc::{format, vec};
use core::cell::Cell;

use crate::base::connection::Connection;
use crate::base::error::ProtocolError;
use crate::base::mock::{cnxn, now, okay, wrte, Mock, MockError, NoAuth};

std::thread_local! {
    /// Bytes `Logcat` has moved within its buffer on this thread, for
    /// the tests that pin how often a byte is copied.
    pub(super) static MOVED: Cell<usize> = const { Cell::new(0) };
}

fn make_v4_entry(
    pid: i32,
    tid: u32,
    sec: i32,
    nsec: i32,
    lid: u32,
    uid: u32,
    payload: &[u8],
) -> Vec<u8> {
    let hdr_size: u16 = HEADER_V4_SIZE as u16;
    let payload_len = payload.len() as u16;
    let mut buf = Vec::with_capacity(HEADER_V4_SIZE + payload.len());
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(&hdr_size.to_le_bytes());
    buf.extend_from_slice(&pid.to_le_bytes());
    buf.extend_from_slice(&tid.to_le_bytes());
    buf.extend_from_slice(&sec.to_le_bytes());
    buf.extend_from_slice(&nsec.to_le_bytes());
    buf.extend_from_slice(&lid.to_le_bytes());
    buf.extend_from_slice(&uid.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn text_payload(priority: u8, tag: &[u8], message: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + tag.len() + 1 + message.len() + 1);
    p.push(priority);
    p.extend_from_slice(tag);
    p.push(0);
    p.extend_from_slice(message);
    p.push(0);
    p
}

#[test]
fn parse_empty_buffer() {
    assert_eq!(parse_entry(&[]), Ok(None));
}

#[test]
fn parse_partial_header() {
    assert_eq!(parse_entry(&[0x10, 0x00]), Ok(None));
}

#[test]
fn parse_incomplete_entry() {
    let data = make_v4_entry(1, 1, 0, 0, 0, 0, b"short");
    assert_eq!(parse_entry(&data[..data.len() - 2]), Ok(None));
}

#[test]
fn parse_invalid_header_size() {
    let mut buf = [0u8; 32];
    buf[0..2].copy_from_slice(&10u16.to_le_bytes());
    buf[2..4].copy_from_slice(&4u16.to_le_bytes());
    assert_eq!(parse_entry(&buf), Err(LogcatError::InvalidHeader));
}

#[test]
fn parse_v4_entry() {
    let payload = text_payload(4, b"MyTag", b"Hello world");
    let data = make_v4_entry(1234, 5678, 1_000_000, 123_456_789, 0, 10042, &payload);

    let (entry, consumed) = parse_entry(&data).unwrap().unwrap();
    assert_eq!(consumed, data.len());
    assert_eq!(entry.pid, 1234);
    assert_eq!(entry.tid, 5678);
    assert_eq!(entry.sec, 1_000_000);
    assert_eq!(entry.nsec, 123_456_789);
    assert_eq!(entry.uid, 10042);
    assert_eq!(entry.log_id, LogId::Main);
    assert_eq!(entry.priority, Priority::Info);
    assert_eq!(entry.tag, b"MyTag");
    assert_eq!(entry.message, b"Hello world");
}

#[test]
fn parse_v3_entry_no_uid() {
    let payload = text_payload(6, b"CrashTag", b"segfault");
    let hdr_size: u16 = HEADER_V3_SIZE as u16;
    let payload_len = payload.len() as u16;
    let mut buf = Vec::new();
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(&hdr_size.to_le_bytes());
    buf.extend_from_slice(&100i32.to_le_bytes());
    buf.extend_from_slice(&200u32.to_le_bytes());
    buf.extend_from_slice(&999i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&payload);

    let (entry, consumed) = parse_entry(&buf).unwrap().unwrap();
    assert_eq!(consumed, buf.len());
    assert_eq!(entry.pid, 100);
    assert_eq!(entry.uid, 0);
    assert_eq!(entry.log_id, LogId::Crash);
    assert_eq!(entry.priority, Priority::Error);
    assert_eq!(entry.tag, b"CrashTag");
    assert_eq!(entry.message, b"segfault");
}

#[test]
fn parse_events_buffer_raw_payload() {
    let raw_event = b"\x01\x02\x03\x04EVENTDATA";
    let data = make_v4_entry(42, 42, 0, 0, 2, 0, raw_event);

    let (entry, _) = parse_entry(&data).unwrap().unwrap();
    assert_eq!(entry.log_id, LogId::Events);
    assert_eq!(entry.priority, Priority::Unknown);
    assert!(entry.tag.is_empty());
    assert_eq!(entry.message, raw_event);
}

#[test]
fn parse_empty_payload() {
    let data = make_v4_entry(1, 1, 0, 0, 0, 0, &[]);
    let (entry, _) = parse_entry(&data).unwrap().unwrap();
    assert_eq!(entry.priority, Priority::Unknown);
    assert!(entry.tag.is_empty());
    assert!(entry.message.is_empty());
}

#[test]
fn parse_two_entries_in_sequence() {
    let p1 = text_payload(2, b"A", b"first");
    let p2 = text_payload(5, b"B", b"second");
    let mut buf = make_v4_entry(1, 1, 0, 0, 0, 0, &p1);
    let second = make_v4_entry(2, 2, 1, 0, 3, 0, &p2);
    buf.extend_from_slice(&second);

    let (e1, c1) = parse_entry(&buf).unwrap().unwrap();
    assert_eq!(e1.tag, b"A");
    assert_eq!(e1.message, b"first");
    assert_eq!(e1.priority, Priority::Verbose);

    let (e2, c2) = parse_entry(&buf[c1..]).unwrap().unwrap();
    assert_eq!(e2.tag, b"B");
    assert_eq!(e2.message, b"second");
    assert_eq!(e2.priority, Priority::Warn);
    assert_eq!(c1 + c2, buf.len());
}

#[test]
fn parse_message_without_trailing_nul() {
    let mut payload = Vec::new();
    payload.push(4);
    payload.extend_from_slice(b"Tag\0");
    payload.extend_from_slice(b"no trailing nul");

    let data = make_v4_entry(1, 1, 0, 0, 0, 0, &payload);
    let (entry, _) = parse_entry(&data).unwrap().unwrap();
    assert_eq!(entry.message, b"no trailing nul");
}

#[test]
fn priority_ordering() {
    assert!(Priority::Verbose < Priority::Debug);
    assert!(Priority::Debug < Priority::Info);
    assert!(Priority::Info < Priority::Warn);
    assert!(Priority::Warn < Priority::Error);
    assert!(Priority::Error < Priority::Fatal);
}

#[test]
fn priority_display_and_char() {
    assert_eq!(Priority::Info.as_char(), 'I');
    assert_eq!(format!("{}", Priority::Error), "ERROR");
}

#[test]
fn log_id_display() {
    assert_eq!(format!("{}", LogId::Main), "main");
    assert_eq!(format!("{}", LogId::Crash), "crash");
}

#[test]
fn tag_and_message_lossy() {
    let entry = LogEntry {
        pid: 0,
        tid: 0,
        sec: 0,
        nsec: 0,
        uid: 0,
        log_id: LogId::Main,
        priority: Priority::Info,
        tag: b"valid".to_vec(),
        message: vec![0xFF, 0xFE, b'!'],
    };
    assert_eq!(entry.tag_lossy(), "valid");
    assert!(entry.message_lossy().contains('!'));
}

#[test]
fn destination_no_args() {
    let mut buf = [0u8; 128];
    let len = write_destination(&mut buf, b"logcat -B", &[]).unwrap();
    assert_eq!(&buf[..len], b"shell,v2,raw:logcat -B\0");
}

#[test]
fn destination_with_args() {
    let mut buf = [0u8; 128];
    let len = write_destination(&mut buf, b"logcat -B", &["-b", "main,system"]).unwrap();
    assert_eq!(&buf[..len], b"shell,v2,raw:logcat -B -b main,system\0");
}

#[test]
fn destination_dump() {
    let mut buf = [0u8; 128];
    let len = write_destination(&mut buf, b"logcat -B -d", &["-t", "50"]).unwrap();
    assert_eq!(&buf[..len], b"shell,v2,raw:logcat -B -d -t 50\0");
}

#[test]
fn destination_text() {
    let mut buf = [0u8; 128];
    let len = write_destination(&mut buf, b"logcat", &["-d", "-v", "threadtime"]).unwrap();
    assert_eq!(&buf[..len], b"shell,v2,raw:logcat -d -v threadtime\0");
}

#[test]
fn destination_buffer_too_small() {
    let mut buf = [0u8; 10];
    assert_eq!(
        write_destination(&mut buf, b"logcat -B", &[]),
        Err(crate::base::destination::DestinationError::TooLong)
    );
}

fn frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(shell_v2::HEADER_SIZE + payload.len());
    f.push(id);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// `n` back-to-back main-buffer entries, each `len` bytes long.
fn entries(n: usize, len: usize) -> Vec<u8> {
    let payload = vec![b'x'; len - HEADER_V4_SIZE];
    let mut out = Vec::with_capacity(n * len);
    for i in 0..n {
        out.extend_from_slice(&make_v4_entry(i as i32, 0, 0, 0, 0, 0, &payload));
    }
    out
}

/// A connection whose logcat channel the device feeds `wrtes`, one WRTE each.
fn device_sending(wrtes: &[&[u8]]) -> Connection<Mock> {
    let mut mock = Mock::new();
    mock.feed(&cnxn()).feed(&okay(1));
    for payload in wrtes {
        mock.feed(&wrte(1, payload));
    }
    now(Connection::<_>::connect(mock, NoAuth, &[])).unwrap()
}

/// Every entry up to the end of logcat's stream, and the bytes moved
/// within `buf` to get them.
fn read_to_end(
    conn: &mut Connection<Mock>,
    buf: &mut [u8],
) -> (Result<Vec<LogEntry>, Error<MockError>>, usize) {
    let mut logcat = now(open(conn, &[], buf)).unwrap();
    MOVED.with(|moved| moved.set(0));
    let mut got = Vec::new();
    let end = loop {
        match now(logcat.read_entry()) {
            Ok(entry) => got.push(entry),
            Err(Error::ChannelClosed) => break Ok(got),
            Err(e) => break Err(e),
        }
    };
    (end, MOVED.with(Cell::get))
}

#[test]
fn a_frame_of_small_entries_is_moved_about_once() {
    // adbd frames whatever one read() of logcat's stdout returned, so a
    // burst like `logcat -d` arrives as one frame of many entries.
    let stdout = entries(2340, HEADER_V4_SIZE);
    let mut wire = frame(shell_v2::STDOUT, &stdout);
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire]);
    let mut buf = vec![0u8; wire.len() + 64];

    let (got, moved) = read_to_end(&mut conn, &mut buf);

    assert_eq!(got.unwrap().len(), 2340);
    assert!(
        moved <= 2 * stdout.len() + buf.len(),
        "moved {moved} bytes for {} bytes of entries",
        stdout.len()
    );
}

#[test]
fn entries_read_on_when_no_frame_ends_where_an_entry_does() {
    // Each frame stops one byte into the next entry, so part of an
    // entry is always left waiting while the stream goes on.
    let stdout = entries(100, HEADER_V4_SIZE);
    let mut wire = frame(shell_v2::STDOUT, &stdout[..HEADER_V4_SIZE + 1]);
    for piece in stdout[HEADER_V4_SIZE + 1..].chunks(HEADER_V4_SIZE) {
        wire.extend_from_slice(&frame(shell_v2::STDOUT, piece));
    }
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire]);
    let mut buf = [0u8; 128];

    let (got, _) = read_to_end(&mut conn, &mut buf);

    assert_eq!(got.unwrap().len(), 100);
}

#[test]
fn a_wrte_of_one_entry_frames_is_moved_about_once() {
    // Streaming logcat flushes every entry, so a burst comes as
    // one-entry frames packed into big WRTEs.
    let stdout = entries(1985, HEADER_V4_SIZE);
    let mut wire = Vec::new();
    for entry in stdout.chunks(HEADER_V4_SIZE) {
        wire.extend_from_slice(&frame(shell_v2::STDOUT, entry));
    }
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire]);
    let mut buf = vec![0u8; wire.len() + 64];

    let (got, moved) = read_to_end(&mut conn, &mut buf);

    assert_eq!(got.unwrap().len(), 1985);
    assert!(
        moved <= 2 * stdout.len() + buf.len(),
        "moved {moved} bytes for {} bytes of entries",
        stdout.len()
    );
}

#[test]
fn a_frame_a_device_never_sends_is_refused() {
    // Only stdout, stderr and exit come from the device; any other id
    // means the stream has slipped out of step.
    let mut wire = frame(shell_v2::WINDOW_SIZE_CHANGE, &[0; 8]);
    wire.extend_from_slice(&frame(shell_v2::STDOUT, &entries(1, HEADER_V4_SIZE)));
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire]);
    let mut buf = [0u8; 256];

    let (got, _) = read_to_end(&mut conn, &mut buf);

    assert!(
        matches!(
            got,
            Err(Error::Protocol(ProtocolError::UnexpectedShellFrame(5)))
        ),
        "got {got:?}"
    );
}

/// Reads `stdout` cut into two frames at `frame_cut`, their wire bytes
/// cut into two WRTEs at `wrte_cut`, through a `buf_len`-byte buffer.
fn read_cut(
    stdout: &[u8],
    frame_cut: usize,
    wrte_cut: usize,
    buf_len: usize,
) -> Result<Vec<LogEntry>, Error<MockError>> {
    let mut wire = frame(shell_v2::STDOUT, &stdout[..frame_cut]);
    wire.extend_from_slice(&frame(shell_v2::STDOUT, &stdout[frame_cut..]));
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire[..wrte_cut], &wire[wrte_cut..]]);
    let mut buf = vec![0u8; buf_len];
    read_to_end(&mut conn, &mut buf).0
}

#[test]
fn a_buffer_four_bytes_longer_than_an_entry_reads_every_cut() {
    // The worst cut leaves all but the last byte of an entry waiting
    // while the next frame's header comes in a few bytes at a time.
    const LEN: usize = 40;
    let stdout = entries(2, LEN);
    let mut ran_out = 0;
    for frame_cut in 1..stdout.len() {
        for wrte_cut in 1..stdout.len() + 16 {
            let got = read_cut(&stdout, frame_cut, wrte_cut, LEN + 4);
            assert_eq!(got.unwrap().len(), 2, "cuts {frame_cut}/{wrte_cut}");
            match read_cut(&stdout, frame_cut, wrte_cut, LEN + 3) {
                Ok(got) => assert_eq!(got.len(), 2),
                Err(Error::ReceiveBufferFull) => ran_out += 1,
                Err(e) => panic!("cuts {frame_cut}/{wrte_cut}: {e:?}"),
            }
        }
    }
    assert!(ran_out > 0, "three bytes over an entry never ran out");
}

#[test]
fn empty_stdout_and_stderr_frames_between_entries_are_harmless() {
    let entry = entries(1, HEADER_V4_SIZE);
    let mut wire = frame(shell_v2::STDOUT, &[]);
    wire.extend_from_slice(&frame(shell_v2::STDOUT, &entry));
    wire.extend_from_slice(&frame(shell_v2::STDERR, &[]));
    wire.extend_from_slice(&frame(shell_v2::STDOUT, &[]));
    wire.extend_from_slice(&frame(shell_v2::STDOUT, &entry));
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire]);
    let mut buf = [0u8; 128];

    let (got, _) = read_to_end(&mut conn, &mut buf);

    assert_eq!(got.unwrap().len(), 2);
}

#[test]
fn an_entry_longer_than_the_buffer_fails_instead_of_waiting() {
    let mut wire = frame(shell_v2::STDOUT, &entries(1, 200));
    wire.extend_from_slice(&frame(shell_v2::EXIT, &[0]));
    let mut conn = device_sending(&[&wire]);
    let mut buf = [0u8; 128];

    let (got, _) = read_to_end(&mut conn, &mut buf);

    assert!(matches!(got, Err(Error::ReceiveBufferFull)), "got {got:?}");
}
