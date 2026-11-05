//! A device that says what it has to say and hangs up. A C read gets
//! all of it in the order it was sent, and only then what ended it:
//! nothing reads the connection in the background, so most of it is
//! still on the socket when the first OKAY fails.

use std::ptr;

#[path = "common/common.rs"]
mod common;
use common::{connect, scripted_adbd, Device, Handle, CMD_CLSE, CMD_WRTE};

const CLASSIC: &str = "shell_v2";
const DELAYED_ACK: &str = "shell_v2,delayed_ack";
/// The id the scripts answer OPENs with.
const CH: u32 = 1;
const CREDIT: u32 = 1 << 20;
const PACKET: usize = 512;
const PACKETS: usize = 64;
/// `ADB_SHELL_V2_STDOUT` and `ADB_SHELL_V2_EXIT` in libadb.h.
const STDOUT: u8 = 1;
const EXIT: u8 = 3;

type Conn = Handle<adb::adb_connection_t>;

/// What the device sends, in which no two packets look alike, so a gap
/// or a swap shows.
fn sent() -> Vec<u8> {
    (0..PACKET * PACKETS).map(|i| (i % 251) as u8).collect()
}

/// Whether the device closes the channel before it hangs up.
#[derive(Clone, Copy, PartialEq)]
enum Goes {
    ClosingTheChannel,
    Abruptly,
}

/// Have the host's channel open and the device gone: it sends what
/// `script` sends, then hangs up before the host reads a byte.
fn open_on_a_device_gone(
    features: &'static str,
    open: impl FnOnce(Conn),
    script: impl FnOnce(&mut Device, u32) + Send + 'static,
) -> Conn {
    let (addr, device) = scripted_adbd(features, move |d| {
        let host = d.accept_open(CH, CREDIT);
        script(d, host);
        d.wait_until_delivered();
    });
    let conn = Handle(connect(&addr, features));
    open(conn);
    device.join().unwrap();
    conn
}

fn channel_on_a_device_gone(features: &'static str, goes: Goes) -> (Conn, u64) {
    let mut id = 0u64;
    let open = |conn: Conn| {
        let dest = b"shell,v2,raw:\0";
        let status =
            unsafe { adb::adb_open_channel(conn.get(), dest.as_ptr(), dest.len(), &mut id) };
        assert_eq!(status, adb::AdbStatus::Ok, "open failed");
    };
    let conn = open_on_a_device_gone(features, open, move |d, host| {
        for packet in sent().chunks(PACKET) {
            d.send(CMD_WRTE, CH, host, packet);
        }
        if goes == Goes::ClosingTheChannel {
            d.send(CMD_CLSE, CH, host, &[]);
        }
    });
    (conn, id)
}

/// `while (adb_read_channel(...) == ADB_OK)`: what it read, and the
/// status that ended it.
fn read_until_it_fails(conn: Conn, id: u64) -> (Vec<u8>, adb::AdbStatus) {
    let mut got = Vec::new();
    let mut buf = [0u8; PACKET];
    let mut n = 0usize;
    loop {
        let status =
            unsafe { adb::adb_read_channel(conn.get(), id, buf.as_mut_ptr(), buf.len(), &mut n) };
        if status != adb::AdbStatus::Ok {
            return (got, status);
        }
        got.extend_from_slice(&buf[..n]);
    }
}

/// `ended_with` is what the call that met the end reports, and `then`
/// what the next one does.
fn all_of_it_comes_back(
    features: &'static str,
    goes: Goes,
    ended_with: adb::AdbStatus,
    then: adb::AdbStatus,
) {
    let (conn, id) = channel_on_a_device_gone(features, goes);
    let (got, status) = read_until_it_fails(conn, id);
    assert!(
        got == sent(),
        "got {} bytes, out of order or short",
        got.len()
    );
    assert_eq!(status, ended_with);
    let (got, status) = read_until_it_fails(conn, id);
    assert!(got.is_empty());
    assert_eq!(status, then);
    unsafe { adb::adb_connection_free(conn.get()) };
}

#[test]
fn a_channel_read_gets_all_a_device_left_under_delayed_ack() {
    all_of_it_comes_back(
        DELAYED_ACK,
        Goes::ClosingTheChannel,
        adb::AdbStatus::ChannelClosed,
        adb::AdbStatus::ChannelClosed,
    );
}

#[test]
fn a_channel_read_gets_all_a_device_left_without_delayed_ack() {
    all_of_it_comes_back(
        CLASSIC,
        Goes::ClosingTheChannel,
        adb::AdbStatus::ChannelClosed,
        adb::AdbStatus::ChannelClosed,
    );
}

/// The call that met the end has only what the transport said to go on,
/// and ADB_ERR_IO is what a timeout looks like too. From the next call on
/// there is no mistaking it.
#[test]
fn a_channel_read_gets_all_a_device_left_with_no_close_under_delayed_ack() {
    all_of_it_comes_back(
        DELAYED_ACK,
        Goes::Abruptly,
        adb::AdbStatus::Io,
        adb::AdbStatus::Disconnected,
    );
}

#[test]
fn a_channel_read_gets_all_a_device_left_with_no_close_without_delayed_ack() {
    all_of_it_comes_back(
        CLASSIC,
        Goes::Abruptly,
        adb::AdbStatus::Io,
        adb::AdbStatus::Disconnected,
    );
}

/// Whatever comes after the end says so, opening a channel included,
/// which would otherwise send an OPEN and wait for an answer.
#[test]
fn every_call_after_the_end_is_told() {
    let (conn, id) = channel_on_a_device_gone(DELAYED_ACK, Goes::Abruptly);
    let (_, status) = read_until_it_fails(conn, id);
    assert_eq!(status, adb::AdbStatus::Io);

    let dest = b"shell,v2,raw:\0";
    let mut other = 0u64;
    let status =
        unsafe { adb::adb_open_channel(conn.get(), dest.as_ptr(), dest.len(), &mut other) };
    assert_eq!(status, adb::AdbStatus::Disconnected);
    let mut len = 0usize;
    let status = unsafe { adb::adb_accept_channel(conn.get(), ptr::null_mut(), 0, &mut len) };
    assert_eq!(status, adb::AdbStatus::Disconnected);
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// One shell_v2 frame: `[id, u32 LE length, payload...]`.
fn frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// The frames of a command that finished, and how `adb_shell_read_frame`
/// took them: the frames, the status that ended the loop, and the one
/// the next call came back with.
fn read_frames(
    features: &'static str,
    goes: Goes,
) -> (Vec<(u8, Vec<u8>)>, adb::AdbStatus, adb::AdbStatus) {
    let mut sh = ptr::null_mut();
    let open = |conn: Conn| {
        let status = unsafe {
            adb::adb_shell_open(
                conn.get(),
                ptr::null(),
                0,
                false,
                ptr::null(),
                0,
                0,
                &mut sh,
            )
        };
        assert_eq!(status, adb::AdbStatus::Ok, "shell open failed");
    };
    let conn = open_on_a_device_gone(features, open, move |d, host| {
        for packet in sent().chunks(PACKET) {
            d.send(CMD_WRTE, CH, host, &frame(STDOUT, packet));
        }
        d.send(CMD_WRTE, CH, host, &frame(EXIT, &[3]));
        if goes == Goes::ClosingTheChannel {
            d.send(CMD_CLSE, CH, host, &[]);
        }
    });

    let mut frames = Vec::new();
    let status = loop {
        let (status, frame) = next_frame(sh);
        if status != adb::AdbStatus::Ok {
            break status;
        }
        frames.push(frame);
    };
    let (then, _) = next_frame(sh);
    unsafe {
        adb::adb_shell_free(sh);
        adb::adb_connection_free(conn.get());
    }
    (frames, status, then)
}

fn next_frame(sh: *mut adb::adb_shell_t) -> (adb::AdbStatus, (u8, Vec<u8>)) {
    let mut buf = [0u8; PACKET];
    let (mut id, mut len) = (0u8, 0usize);
    let status =
        unsafe { adb::adb_shell_read_frame(sh, &mut id, buf.as_mut_ptr(), buf.len(), &mut len) };
    (status, (id, buf[..len].to_vec()))
}

fn all_the_frames() -> Vec<(u8, Vec<u8>)> {
    let mut frames: Vec<_> = sent()
        .chunks(PACKET)
        .map(|packet| (STDOUT, packet.to_vec()))
        .collect();
    frames.push((EXIT, vec![3]));
    frames
}

#[test]
fn a_shell_read_gets_every_frame_a_device_left() {
    for features in [DELAYED_ACK, CLASSIC] {
        let (frames, status, then) = read_frames(features, Goes::ClosingTheChannel);
        assert!(frames == all_the_frames(), "{} frames", frames.len());
        assert_eq!(status, adb::AdbStatus::ChannelClosed);
        assert_eq!(then, adb::AdbStatus::ChannelClosed);
    }
}

#[test]
fn a_shell_read_gets_every_frame_a_device_left_with_no_close() {
    for features in [DELAYED_ACK, CLASSIC] {
        let (frames, status, then) = read_frames(features, Goes::Abruptly);
        assert!(frames == all_the_frames(), "{} frames", frames.len());
        assert_eq!(status, adb::AdbStatus::Io);
        assert_eq!(then, adb::AdbStatus::Disconnected);
    }
}
