//! Two C threads writing stdin on one shell session must not interleave
//! their frames.

use std::ffi::{c_void, CString};
use std::ptr;
use std::thread;

#[path = "common/common.rs"]
mod common;
use common::{fake_adbd, FRAME_LEN};

/// Split a shell_v2 byte stream into `(id, payload)` frames.
fn frames(mut stream: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while stream.len() >= 5 {
        let id = stream[0];
        let len = u32::from_le_bytes([stream[1], stream[2], stream[3], stream[4]]) as usize;
        assert!(
            stream.len() >= 5 + len,
            "frame claims {len} bytes with only {} left: the stream is interleaved",
            stream.len() - 5
        );
        out.push((id, stream[5..5 + len].to_vec()));
        stream = &stream[5 + len..];
    }
    assert!(stream.is_empty(), "{} trailing bytes", stream.len());
    out
}

/// The fake device never asks for AUTH, so this is only here to satisfy
/// the handshake API.
unsafe extern "C" fn never_signs(
    _user_data: *mut c_void,
    _token: *const u8,
    _token_len: usize,
    _out_signature: *mut u8,
    _out_capacity: usize,
    _out_length: *mut usize,
) -> adb::AdbStatus {
    adb::AdbStatus::Auth
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
