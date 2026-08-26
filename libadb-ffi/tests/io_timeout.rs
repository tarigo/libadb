//! A read timeout set through the C API surfaces as ADB_ERR_IO and
//! leaves the connection usable, instead of parking the caller forever
//! on a silent device.

use std::ffi::{c_void, CString};
use std::ptr;
use std::time::Instant;

#[path = "common/common.rs"]
mod common;
use common::fake_adbd_pushing;

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

#[test]
fn a_read_timeout_fails_with_io_and_keeps_the_connection() {
    // One pushed WRTE, then silence.
    let (addr, _rx, _parked) = fake_adbd_pushing(vec![b"hello".to_vec()]);
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2,delayed_ack").unwrap();
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

    let dest = b"shell,v2,raw:\0";
    let mut id = 0u64;
    let status = unsafe { adb::adb_open_channel(conn, dest.as_ptr(), dest.len(), &mut id) };
    assert_eq!(status, adb::AdbStatus::Ok, "open failed");

    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn, 300, 0) };
    assert_eq!(status, adb::AdbStatus::Ok, "set_io_timeout failed");

    // The pushed data arrives fine...
    let mut buf = [0u8; 32];
    let mut read = 0usize;
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    assert_eq!(status, adb::AdbStatus::Ok, "first read failed");
    assert_eq!(&buf[..read], b"hello");

    // ...and the silence after it comes back as Io within the timeout,
    // not as an eternal park.
    let t0 = Instant::now();
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    assert_eq!(status, adb::AdbStatus::Io, "expected a timeout Io error");
    assert!(t0.elapsed().as_secs() < 5, "timeout did not fire in time");

    unsafe { adb::adb_connection_free(conn) };
}

/// A device that sends half a WRTE, then holds the rest until the test
/// releases it — the partially received packet must survive the
/// timed-out read. The halves are coordinated, not timed.
#[allow(clippy::type_complexity)]
fn half_then_rest_adbd() -> (
    String,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    use common::{
        header, read_packet, CMD_CNXN, CMD_OKAY, CMD_OPEN, CMD_WRTE, MAX_PAYLOAD, VERSION,
    };
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (half_tx, half_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).unwrap();
        while let Some((cmd, arg0, _payload)) = read_packet(&mut stream) {
            match cmd {
                CMD_CNXN => {
                    let banner = b"device::features=shell_v2,delayed_ack";
                    stream
                        .write_all(&header(CMD_CNXN, VERSION, MAX_PAYLOAD, banner))
                        .unwrap();
                }
                CMD_OPEN => {
                    let remote_id = arg0;
                    let budget = 1_000_000u32.to_le_bytes();
                    stream
                        .write_all(&header(CMD_OKAY, 1, remote_id, &budget))
                        .unwrap();
                    let wrte = header(CMD_WRTE, 1, remote_id, b"hello");
                    let (first, rest) = wrte.split_at(wrte.len() / 2);
                    stream.write_all(first).unwrap();
                    stream.flush().unwrap();
                    let _ = half_tx.send(());
                    let _ = release_rx.recv();
                    stream.write_all(rest).unwrap();
                }
                _ => return,
            }
        }
    });
    (addr, half_rx, release_tx)
}

#[test]
fn a_packet_split_by_a_timeout_survives_it() {
    let (addr, half_rx, release_tx) = half_then_rest_adbd();
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2,delayed_ack").unwrap();
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

    let dest = b"shell,v2,raw:\0";
    let mut id = 0u64;
    let status = unsafe { adb::adb_open_channel(conn, dest.as_ptr(), dest.len(), &mut id) };
    assert_eq!(status, adb::AdbStatus::Ok, "open failed");

    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn, 300, 0) };
    assert_eq!(status, adb::AdbStatus::Ok, "set_io_timeout failed");

    // The device confirms half the packet is on the wire — and holds
    // the rest, so this read can only end in the timeout.
    half_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the device never sent the first half");
    let mut buf = [0u8; 32];
    let mut read = 0usize;
    let t0 = Instant::now();
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    assert_eq!(status, adb::AdbStatus::Io, "expected a mid-packet timeout");
    assert!(
        t0.elapsed().as_secs() < 5,
        "timed out, not waited out: {:?}",
        t0.elapsed()
    );

    // Only now may the rest go out; the buffered half must still be
    // there for the packet to come out whole.
    release_tx.send(()).unwrap();
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    assert_eq!(status, adb::AdbStatus::Ok, "read after the stall failed");
    assert_eq!(&buf[..read], b"hello", "the packet lost its first half");

    unsafe { adb::adb_connection_free(conn) };
}

/// A device that grants a huge budget and then never reads: writes
/// pile into the socket until the buffers are full and the write
/// timeout fires.
fn deaf_adbd() -> String {
    use common::{header, read_packet, CMD_CNXN, CMD_OKAY, CMD_OPEN, MAX_PAYLOAD, VERSION};
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).unwrap();
        while let Some((cmd, arg0, _payload)) = read_packet(&mut stream) {
            match cmd {
                CMD_CNXN => {
                    let banner = b"device::features=shell_v2,delayed_ack";
                    stream
                        .write_all(&header(CMD_CNXN, VERSION, MAX_PAYLOAD, banner))
                        .unwrap();
                }
                CMD_OPEN => {
                    let budget = (1u32 << 30).to_le_bytes();
                    stream
                        .write_all(&header(CMD_OKAY, 1, arg0, &budget))
                        .unwrap();
                    // Deaf from here on: keep the socket open, read
                    // nothing, let the buffers fill.
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    return;
                }
                _ => return,
            }
        }
    });
    addr
}

#[test]
fn a_write_timeout_fails_with_io_and_desynchronizes() {
    let addr = deaf_adbd();
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new("host::features=shell_v2,delayed_ack").unwrap();
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

    let dest = b"shell,v2,raw:\0";
    let mut id = 0u64;
    let status = unsafe { adb::adb_open_channel(conn, dest.as_ptr(), dest.len(), &mut id) };
    assert_eq!(status, adb::AdbStatus::Ok, "open failed");

    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn, 0, 300) };
    assert_eq!(status, adb::AdbStatus::Ok, "set_io_timeout failed");

    // Pump data at a peer that never reads. Once both socket buffers
    // are full, a write blocks past the timeout and fails with Io.
    let chunk = vec![0x61u8; 256 * 1024];
    let mut saw_io = false;
    let t0 = Instant::now();
    for _ in 0..256 {
        let status = unsafe { adb::adb_write_channel(conn, id, chunk.as_ptr(), chunk.len()) };
        if status == adb::AdbStatus::Io {
            saw_io = true;
            break;
        }
        assert_eq!(status, adb::AdbStatus::Ok, "write failed early");
        assert!(t0.elapsed().as_secs() < 30, "writes never blocked");
    }
    assert!(saw_io, "the write timeout never fired");

    // The abandoned mid-packet write poisons the connection: channel
    // operations now answer with the dedicated status.
    let status = unsafe { adb::adb_write_channel(conn, id, chunk.as_ptr(), chunk.len()) };
    assert_eq!(
        status,
        adb::AdbStatus::Desynchronized,
        "expected a poisoned connection"
    );

    // Metadata still answers.
    assert!(unsafe { adb::adb_connection_max_payload(conn) } > 0);

    unsafe { adb::adb_connection_free(conn) };
}
