//! Two C threads writing stdin on one shell session must not interleave
//! their frames.

use std::ffi::{c_void, CString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::mpsc;
use std::thread;

const CMD_CNXN: u32 = 0x4e58_4e43;
const CMD_OPEN: u32 = 0x4e45_504f;
const CMD_OKAY: u32 = 0x5941_4b4f;
const CMD_WRTE: u32 = 0x4554_5257;
const CMD_CLSE: u32 = 0x4553_4c43;

/// Protocol version that skips payload checksums, so neither side has to
/// compute them.
const VERSION: u32 = 0x0100_0001;
/// Small enough that a frame has to be split across many WRTEs, which
/// is where interleaving shows up.
const MAX_PAYLOAD: u32 = 1024;
const FRAME_LEN: usize = 16 * 1024;

fn header(cmd: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + payload.len());
    v.extend_from_slice(&cmd.to_le_bytes());
    v.extend_from_slice(&arg0.to_le_bytes());
    v.extend_from_slice(&arg1.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(cmd ^ 0xFFFF_FFFF).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn read_packet(stream: &mut TcpStream) -> Option<(u32, u32, Vec<u8>)> {
    let mut h = [0u8; 24];
    stream.read_exact(&mut h).ok()?;
    let cmd = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let arg0 = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    let len = u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).ok()?;
    }
    Some((cmd, arg0, payload))
}

/// A device that accepts one connection, opens one channel and records
/// every byte written to it, in arrival order.
///
/// The second receiver fires once, when the first sender is provably
/// parked in the middle of its first frame — the moment the second
/// sender must enter for the two to contend. It carries a confirmation
/// sender: the device holds the parking ack until the test confirms
/// through it that the second sender is entering its write.
fn fake_adbd() -> (
    String,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<mpsc::Sender<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    let (parked_tx, parked_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // The test paces itself by acknowledgement round-trips; without
        // this, Nagle turns each of them into a 40 ms stall.
        stream.set_nodelay(true).unwrap();
        let mut channel_stream = Vec::new();
        let mut remote_id = 0u32;
        let mut wrte_seen = 0u32;

        while let Some((cmd, arg0, payload)) = read_packet(&mut stream) {
            match cmd {
                CMD_CNXN => {
                    let banner = b"device::features=shell_v2";
                    stream
                        .write_all(&header(CMD_CNXN, VERSION, MAX_PAYLOAD, banner))
                        .unwrap();
                }
                CMD_OPEN => {
                    remote_id = arg0;
                    stream
                        .write_all(&header(CMD_OKAY, 1, remote_id, &[]))
                        .unwrap();
                }
                CMD_WRTE => {
                    channel_stream.extend_from_slice(&payload);
                    wrte_seen += 1;
                    if wrte_seen == 2 {
                        // Header and first chunk received, and the ack
                        // they are waiting for is the one being held:
                        // the first sender is parked mid-frame. Let the
                        // second sender in, wait until it confirms it
                        // is entering its write, and grace the last few
                        // instructions between that confirmation and
                        // the credit wait before releasing the grant.
                        // This grant is not the only chance: the
                        // metering below re-runs the contest at every
                        // later acknowledgement.
                        let (confirm_tx, confirm_rx) = mpsc::channel();
                        let _ = parked_tx.send(confirm_tx);
                        let _ = confirm_rx.recv_timeout(std::time::Duration::from_secs(10));
                        thread::sleep(std::time::Duration::from_millis(25));
                    } else {
                        // Meter every other acknowledgement too. Each
                        // WRTE spends the channel's send budget, so at
                        // each grant the sender that just wrote is
                        // parked and the other has had time to queue on
                        // the same wake. An implementation that does
                        // not hold the frame lock has to win that race
                        // at every WRTE of every frame.
                        thread::sleep(std::time::Duration::from_millis(2));
                    }
                    stream
                        .write_all(&header(CMD_OKAY, 1, remote_id, &[]))
                        .unwrap();
                }
                CMD_CLSE => {
                    stream
                        .write_all(&header(CMD_CLSE, 1, remote_id, &[]))
                        .unwrap();
                    break;
                }
                _ => {}
            }
        }
        let _ = tx.send(channel_stream);
    });

    (addr, rx, parked_rx)
}

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
