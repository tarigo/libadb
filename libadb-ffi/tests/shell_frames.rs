//! Two C threads writing stdin on one shell session must not interleave
//! their frames, a session whose request would reach the device
//! rewritten is never opened, and closing stdin tells a device that
//! left first from a session closed here.

use std::ffi::{c_void, CStr, CString};
use std::io::Write as _;
use std::net::TcpListener;
use std::ptr;
use std::thread;

#[path = "common/common.rs"]
mod common;
use common::{
    connect, fake_adbd, frames, header, read_packet, scripted_adbd, within, Handle, CMD_CLSE,
    CMD_CNXN, CMD_OKAY, CMD_OPEN, CMD_WRTE, FRAME_LEN, MAX_PAYLOAD, VERSION,
};

/// The fake device never asks for AUTH, so this is only here to satisfy
/// the handshake API.
unsafe extern "C" fn never_signs(
    _user_data: *mut c_void,
    _token: *const u8,
    _token_len: usize,
    _out_signature: *mut u8,
    _out_capacity: usize,
    _out_length: *mut usize,
) -> i32 {
    adb::AdbStatus::Auth as i32
}

/// `adb_shell_t` is `Send + Sync` by construction (the crate asserts
/// it); this carries the raw pointer across the thread boundary.
struct ShellPtr(*mut adb::adb_shell_t);
unsafe impl Send for ShellPtr {}
unsafe impl Sync for ShellPtr {}

#[test]
fn concurrent_stdin_writes_keep_their_frames_whole() {
    let (addr, rx, parked) = fake_adbd();
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2").unwrap();

    let pubkey = b"unused\0";
    let auth = adb::adb_authenticator_t {
        public_key: pubkey.as_ptr(),
        public_key_len: pubkey.len(),
        sign: Some(never_signs),
        user_data: ptr::null_mut(),
    };

    let mut conn = ptr::null_mut();
    let status = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(status, adb::AdbStatus::Ok, "connect failed");

    let mut sh = ptr::null_mut();
    let status =
        unsafe { adb::adb_shell_open(conn, ptr::null(), 0, false, ptr::null(), 0, 0, &mut sh) };
    assert_eq!(status, adb::AdbStatus::Ok, "shell open failed");

    // Each frame is many times `MAX_PAYLOAD`, so every one of them is
    // split across WRTEs, and each WRTE waits for the device's OKAY
    // before the next one may go out. The device holds the ack the
    // first sender needs mid-frame until the second sender has entered
    // (see `fake_adbd`) — the exact ordering the frame lock exists to
    // forbid — and meters every later ack so the senders stay in
    // contention for the rest of the run.
    let payloads = [vec![b'a'; FRAME_LEN], vec![b'b'; FRAME_LEN]];
    let shell = ShellPtr(sh);
    let reader = ShellPtr(sh);
    let reader = thread::spawn(move || {
        let reader = reader;
        let mut id = 0u8;
        let mut buf = vec![0u8; 64 * 1024];
        let mut len = 0usize;
        loop {
            let status = unsafe {
                adb::adb_shell_read_frame(reader.0, &mut id, buf.as_mut_ptr(), buf.len(), &mut len)
            };
            if status != adb::AdbStatus::Ok {
                break;
            }
        }
    });

    thread::scope(|scope| {
        let (first, second) = (&payloads[0], &payloads[1]);
        let shell = &shell;
        scope.spawn(move || {
            for _ in 0..4 {
                let status =
                    unsafe { adb::adb_shell_write_stdin(shell.0, first.as_ptr(), first.len()) };
                assert_eq!(status, adb::AdbStatus::Ok, "write_stdin failed");
            }
        });
        scope.spawn(move || {
            // Not scheduling luck: enter only once the device reports
            // the first sender parked inside its first frame, and
            // confirm entry back — the device holds that sender's ack
            // until this thread is provably running and committed to
            // the call below.
            let confirm = parked
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the first sender never parked mid-frame");
            confirm.send(()).unwrap();
            for _ in 0..4 {
                let status =
                    unsafe { adb::adb_shell_write_stdin(shell.0, second.as_ptr(), second.len()) };
                assert_eq!(status, adb::AdbStatus::Ok, "write_stdin failed");
            }
        });
    });

    // Close first: the reader is parked in `read_frame` and only comes
    // back once the channel is gone. Freeing before it returns would
    // pull the handle out from under it.
    unsafe { adb::adb_shell_close(sh) };
    reader.join().unwrap();
    unsafe {
        adb::adb_shell_free(sh);
        adb::adb_connection_free(conn);
    }

    let stream = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    let frames = frames(&stream);
    assert_eq!(
        frames.len(),
        8,
        "expected eight frames, got {}",
        frames.len()
    );
    for (id, payload) in frames {
        assert_eq!(id, 0, "unexpected frame id {id}");
        assert_eq!(payload.len(), FRAME_LEN, "frame lost or gained bytes");
        let first = payload[0];
        assert!(
            payload.iter().all(|&b| b == first),
            "a frame carries bytes from both writers"
        );
    }
}

#[test]
fn a_term_that_would_rewrite_the_request_opens_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let device = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let (cmd, _, _) = read_packet(&mut s).expect("the host opens with CNXN");
        assert_eq!(cmd, CMD_CNXN);
        s.write_all(&header(
            CMD_CNXN,
            VERSION,
            MAX_PAYLOAD,
            b"device::features=shell_v2",
        ))
        .unwrap();
        // Whatever arrives until the host hangs up. An OPEN is refused,
        // so a host that sends one fails rather than waits.
        let mut after = Vec::new();
        while let Some((cmd, host_id, payload)) = read_packet(&mut s) {
            if cmd == CMD_OPEN {
                s.write_all(&header(CMD_CLSE, 0, host_id, &[])).unwrap();
            }
            after.push((cmd.to_le_bytes(), payload));
        }
        after
    });

    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2").unwrap();
    let pubkey = b"unused\0";
    let auth = adb::adb_authenticator_t {
        public_key: pubkey.as_ptr(),
        public_key_len: pubkey.len(),
        sign: Some(never_signs),
        user_data: ptr::null_mut(),
    };
    let mut conn = ptr::null_mut();
    let status = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(status, adb::AdbStatus::Ok, "connect failed");

    // adbd would take `raw` for the mode and drop the PTY, or run `x:ls`.
    for term in ["xterm,raw", "xterm:x"] {
        let c_term = CString::new(term).unwrap();
        let command = b"ls";
        let mut sh = ptr::null_mut();
        let status = unsafe {
            adb::adb_shell_open(
                conn,
                command.as_ptr(),
                command.len(),
                true,
                c_term.as_ptr(),
                0,
                0,
                &mut sh,
            )
        };
        assert_eq!(status, adb::AdbStatus::Protocol, "{term:?}");
        assert!(sh.is_null(), "{term:?}: a refused session has no handle");
    }

    unsafe { adb::adb_connection_free(conn) };
    let after = device.join().unwrap();
    assert!(after.is_empty(), "nothing follows the handshake: {after:?}");
}

/// `ADB_SHELL_V2_STDOUT` and `ADB_SHELL_V2_CLOSE_STDIN` in libadb.h.
const STDOUT: u8 = 1;
const CLOSE_STDIN: u8 = 4;

type Shell = Handle<adb::adb_shell_t>;

fn open_shell(conn: *mut adb::adb_connection_t) -> Shell {
    let mut sh = ptr::null_mut();
    let status =
        unsafe { adb::adb_shell_open(conn, ptr::null(), 0, false, ptr::null(), 0, 0, &mut sh) };
    assert_eq!(status, adb::AdbStatus::Ok, "shell open failed");
    Handle(sh)
}

fn read_frame(sh: Shell) -> (adb::AdbStatus, u8, Vec<u8>) {
    let mut id = 0u8;
    let mut buf = [0u8; 64];
    let mut len = 0usize;
    let status = unsafe {
        adb::adb_shell_read_frame(sh.get(), &mut id, buf.as_mut_ptr(), buf.len(), &mut len)
    };
    (status, id, buf[..len].to_vec())
}

fn write_stdin(sh: Shell, data: &[u8]) -> adb::AdbStatus {
    unsafe { adb::adb_shell_write_stdin(sh.get(), data.as_ptr(), data.len()) }
}

/// A shell_v2 frame as a device writes it.
fn frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// A command can finish before its caller gets to close stdin. Nothing
/// is wrong then: the CLOSE_STDIN has nowhere to go and is not sent.
#[test]
fn closing_stdin_after_the_device_left_is_no_failure() {
    let (addr, device) = scripted_adbd("shell_v2", |d| {
        let host = d.accept_open(1, 0);
        d.send(CMD_CLSE, 1, host, &[]);
        let mut sent = Vec::new();
        while let Some(pkt) = d.recv() {
            sent.push(pkt.cmd);
        }
        sent
    });
    let conn = connect(&addr, "shell_v2");
    let sh = open_shell(conn);

    let (status, ..) = within("the read", move || read_frame(sh));
    assert_eq!(status, adb::AdbStatus::ChannelClosed, "CLSE dispatched");

    let status = unsafe { adb::adb_shell_close_stdin(sh.get()) };
    assert_eq!(status, adb::AdbStatus::Ok);

    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn);
    }
    let sent = within("the device", move || device.join().unwrap());
    assert!(!sent.contains(&CMD_WRTE), "a frame on a closed channel");
}

/// The same with the CLSE received by a stdin write waiting for the
/// device: what came ahead of it can still be read afterwards.
#[test]
fn closing_stdin_leaves_what_the_device_wrote_readable() {
    let (addr, device) = scripted_adbd("shell_v2", |d| {
        let host = d.accept_open(1, 0);
        d.recv_cmd(CMD_WRTE);
        d.send(CMD_WRTE, 1, host, &frame(STDOUT, b"bye"));
        d.send(CMD_CLSE, 1, host, &[]);
        while d.recv().is_some() {}
    });
    let conn = connect(&addr, "shell_v2");
    let sh = open_shell(conn);

    let status = within("the write", move || write_stdin(sh, b"x"));
    assert_eq!(status, adb::AdbStatus::ChannelClosed, "CLSE dispatched");

    let status = unsafe { adb::adb_shell_close_stdin(sh.get()) };
    assert_eq!(status, adb::AdbStatus::Ok);

    let (status, id, payload) = within("the read", move || read_frame(sh));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!((id, payload.as_slice()), (STDOUT, &b"bye"[..]));
    let (status, ..) = within("the read after it", move || read_frame(sh));
    assert_eq!(status, adb::AdbStatus::ChannelClosed);

    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn);
    }
    within("the device", move || device.join().unwrap());
}

/// After `adb_shell_close` the session is closed, even if the device
/// closed the channel first: a caller that closes stdin on a closed
/// handle has a bug and should hear of it.
#[test]
fn closing_stdin_after_a_local_close_fails() {
    let (addr, device) = scripted_adbd("shell_v2", |d| {
        let host = d.accept_open(1, 0);
        d.send(CMD_CLSE, 1, host, &[]);
        while d.recv().is_some() {}
    });
    let conn = connect(&addr, "shell_v2");
    let sh = open_shell(conn);

    let (status, ..) = within("the read", move || read_frame(sh));
    assert_eq!(status, adb::AdbStatus::ChannelClosed, "CLSE dispatched");

    let status = unsafe { adb::adb_shell_close(sh.get()) };
    assert_eq!(status, adb::AdbStatus::Ok);
    let status = unsafe { adb::adb_shell_close_stdin(sh.get()) };
    assert_eq!(status, adb::AdbStatus::ChannelClosed);

    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn);
    }
    within("the device", move || device.join().unwrap());
}

#[test]
fn a_read_after_a_local_close_says_why_it_failed() {
    let (addr, device) = scripted_adbd("shell_v2", |d| {
        d.accept_open(1, 0);
        while d.recv().is_some() {}
    });
    let conn = connect(&addr, "shell_v2");
    let sh = open_shell(conn);

    let status = unsafe { adb::adb_shell_close(sh.get()) };
    assert_eq!(status, adb::AdbStatus::Ok);
    let (status, ..) = read_frame(sh);
    assert_eq!(status, adb::AdbStatus::ChannelClosed);
    let text = adb::adb_last_error();
    assert!(!text.is_null(), "no text for the failed read");
    let text = unsafe { CStr::from_ptr(text) }.to_string_lossy();
    assert_eq!(text, "channel closed");

    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn);
    }
    within("the device", move || device.join().unwrap());
}

#[test]
fn closing_stdin_on_a_live_channel_sends_the_frame() {
    let (addr, device) = scripted_adbd("shell_v2", |d| {
        let host = d.accept_open(1, 0);
        d.take(1, host, 5)
    });
    let conn = connect(&addr, "shell_v2");
    let sh = open_shell(conn);

    let status = unsafe { adb::adb_shell_close_stdin(sh.get()) };
    assert_eq!(status, adb::AdbStatus::Ok);

    let stream = within("the device", move || device.join().unwrap());
    assert_eq!(frames(&stream), [(CLOSE_STDIN, Vec::new())]);
    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn);
    }
}

/// A channel a fault closed is not one the device left. An OKAY without
/// its credit closes the channel when a parked write receives it, where
/// a read would only fail.
#[test]
fn closing_stdin_after_a_fault_reports_the_fault() {
    const FEATURES: &str = "shell_v2,delayed_ack";
    let (addr, device) = scripted_adbd(FEATURES, |d| {
        let host = d.accept_open(1, 1);
        d.recv_cmd(CMD_WRTE);
        d.send(CMD_OKAY, 1, host, &[]);
        d.recv_cmd(CMD_CLSE);
    });
    let conn = connect(&addr, FEATURES);
    let sh = open_shell(conn);

    let status = within("the write", move || write_stdin(sh, b"x"));
    assert_eq!(status, adb::AdbStatus::Protocol);

    let status = unsafe { adb::adb_shell_close_stdin(sh.get()) };
    assert_eq!(status, adb::AdbStatus::Protocol);

    within("the device", move || device.join().unwrap());
    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn);
    }
}
