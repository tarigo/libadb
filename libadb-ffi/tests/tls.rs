//! `adb_connect` against a device that demands TLS, the way an Android
//! 11+ wireless-debugging port does.

#![cfg(feature = "tls")]

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[path = "common/common.rs"]
mod common;

#[path = "tls_device/tls_device.rs"]
mod tls_device;

use common::{fake_adbd_pushing, STLS_VERSION};
use tls_device::{host_key, HostKey, KeyPolicy};

const BANNER: &str = "host::features=shell_v2,delayed_ack";

/// `adb_connect` to `addr` with `key`.
fn connect(addr: &str, key: &HostKey) -> (adb::AdbStatus, *mut adb::adb_connection_t) {
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new(BANNER).unwrap();
    let mut conn = ptr::null_mut();
    let status = unsafe {
        adb::adb_connect(
            uri.as_ptr(),
            key.pem.as_ptr(),
            key.public.as_ptr(),
            banner.as_ptr(),
            &mut conn,
        )
    };
    (status, conn)
}

fn last_error() -> String {
    let p = adb::adb_last_error();
    assert!(!p.is_null(), "no error message was set");
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn open_shell(conn: *mut adb::adb_connection_t) -> u64 {
    let dest = b"shell,v2,raw:\0";
    let mut id = 0u64;
    let status = unsafe { adb::adb_open_channel(conn, dest.as_ptr(), dest.len(), &mut id) };
    assert_eq!(status, adb::AdbStatus::Ok, "open failed: {}", last_error());
    id
}

fn read(conn: *mut adb::adb_connection_t, id: u64) -> (adb::AdbStatus, Vec<u8>) {
    let mut buf = [0u8; 64];
    let mut read = 0usize;
    let status = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut read) };
    (status, buf[..read].to_vec())
}

#[test]
fn a_device_that_demands_tls_is_served_through_adb_connect() {
    // The device trusts one key only, so getting through at all shows
    // the certificate carried the caller's.
    let key = host_key();
    let (addr, device) =
        tls_device::spawn(KeyPolicy::Trust(key.spki.clone()), vec![b"hello".to_vec()]);

    let (status, conn) = connect(&addr, key);
    assert_eq!(
        status,
        adb::AdbStatus::Ok,
        "connect failed: {}",
        last_error()
    );

    let id = open_shell(conn);
    let (status, data) = read(conn, id);
    assert_eq!(status, adb::AdbStatus::Ok, "read failed: {}", last_error());
    assert_eq!(data, b"hello");

    let ping = b"ping";
    let status = unsafe { adb::adb_write_channel(conn, id, ping.as_ptr(), ping.len()) };
    assert_eq!(status, adb::AdbStatus::Ok, "write failed: {}", last_error());
    let status = unsafe { adb::adb_close_channel(conn, id) };
    assert_eq!(status, adb::AdbStatus::Ok, "close failed: {}", last_error());
    unsafe { adb::adb_connection_free(conn) };

    let (report, served) = device.join().unwrap();
    assert_eq!(report.host_stls_version, STLS_VERSION);
    assert!(!report.refused_key);
    assert_eq!(served.expect("the session was served"), b"ping");
}

#[test]
fn a_key_the_device_does_not_trust_is_auth_with_pairing_advice() {
    let (addr, device) = tls_device::spawn(KeyPolicy::Reject, Vec::new());

    let (status, conn) = connect(&addr, host_key());
    assert_eq!(status, adb::AdbStatus::Auth, "{}", last_error());
    assert!(conn.is_null(), "a refused key must not hand out a handle");
    let message = last_error();
    assert!(message.contains("adb pair"), "{message}");

    let (report, served) = device.join().unwrap();
    assert!(report.refused_key, "the device did not refuse the key");
    assert!(served.is_none());
}

#[test]
fn a_plain_device_is_still_served_in_the_clear() {
    let (addr, _rx, _) = fake_adbd_pushing(vec![b"hello".to_vec()]);

    let (status, conn) = connect(&addr, host_key());
    assert_eq!(
        status,
        adb::AdbStatus::Ok,
        "connect failed: {}",
        last_error()
    );

    let id = open_shell(conn);
    let (status, data) = read(conn, id);
    assert_eq!(status, adb::AdbStatus::Ok, "read failed: {}", last_error());
    assert_eq!(data, b"hello");
    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn a_device_that_hangs_up_mid_handshake_is_io_not_auth() {
    // Under TLS 1.3 the host's certificate travels in its last flight.
    // A device gone before then never saw the key, and pairing again
    // would cure nothing.
    let (addr, device) = tls_device::spawn_hanging_up_mid_handshake();

    let (status, conn) = connect(&addr, host_key());
    assert_eq!(status, adb::AdbStatus::Io, "{}", last_error());
    assert!(conn.is_null());
    let message = last_error();
    assert!(message.contains("handshake"), "{message}");
    assert!(!message.contains("adb pair"), "{message}");
    device.join().unwrap();
}

// Unix-only, like its plaintext twin: the recoverable-read guarantee is
// not promised on Windows.
#[cfg(unix)]
#[test]
fn a_packet_split_by_a_timeout_survives_it_over_tls() {
    use common::{header, read_packet, CMD_OKAY, CMD_OPEN, CMD_WRTE};
    use std::io::Write as _;

    let (half_tx, half_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let key = host_key();
    let (addr, device) = tls_device::spawn_with(
        KeyPolicy::Trust(key.spki.clone()),
        move |tls, delayed_ack| {
            let (cmd, remote_id, _) = read_packet(tls).expect("the host opens a channel");
            assert_eq!(cmd, CMD_OPEN);
            let budget = 1_000_000u32.to_le_bytes();
            let credit: &[u8] = if delayed_ack { &budget } else { &[] };
            tls.write_all(&header(CMD_OKAY, 1, remote_id, credit))
                .unwrap();
            tls.flush().unwrap();

            // Each flush seals a record, so the two halves reach the
            // host as two records, the second held until released.
            let wrte = header(CMD_WRTE, 1, remote_id, b"hello");
            let (first, rest) = wrte.split_at(wrte.len() / 2);
            tls.write_all(first).unwrap();
            tls.flush().unwrap();
            let _ = half_tx.send(());
            let _ = release_rx.recv();
            tls.write_all(rest).unwrap();
            tls.flush().unwrap();
            // Stay until the host is done, or the close would race the
            // last record.
            let _ = read_packet(tls);
        },
    );

    let (status, conn) = connect(&addr, key);
    assert_eq!(
        status,
        adb::AdbStatus::Ok,
        "connect failed: {}",
        last_error()
    );
    let id = open_shell(conn);
    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn, 300, 0) };
    assert_eq!(status, adb::AdbStatus::Ok, "set_io_timeout failed");

    half_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the device never sent the first half");
    let t0 = Instant::now();
    let (status, _) = read(conn, id);
    assert_eq!(status, adb::AdbStatus::Io, "expected a mid-packet timeout");
    assert!(
        t0.elapsed().as_secs() < 5,
        "timed out, not waited out: {:?}",
        t0.elapsed()
    );

    release_tx.send(()).unwrap();
    let (status, data) = read(conn, id);
    assert_eq!(
        status,
        adb::AdbStatus::Ok,
        "read after the stall failed: {}",
        last_error()
    );
    assert_eq!(data, b"hello", "the packet lost its first half");

    unsafe { adb::adb_connection_free(conn) };
    device.join().unwrap();
}

#[test]
fn a_write_timeout_over_tls_fails_with_io_and_desynchronizes() {
    use common::{header, read_packet, CMD_OKAY, CMD_OPEN};
    use std::io::Write as _;

    // A device that grants a huge budget and then never reads: writes
    // pile into the socket until the buffers are full and the write
    // timeout fires.
    let key = host_key();
    let (addr, _device) =
        tls_device::spawn_with(KeyPolicy::Trust(key.spki.clone()), |tls, _delayed_ack| {
            let (cmd, remote_id, _) = read_packet(tls).expect("the host opens a channel");
            assert_eq!(cmd, CMD_OPEN);
            let budget = (1u32 << 30).to_le_bytes();
            tls.write_all(&header(CMD_OKAY, 1, remote_id, &budget))
                .unwrap();
            tls.flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
        });

    let (status, conn) = connect(&addr, key);
    assert_eq!(
        status,
        adb::AdbStatus::Ok,
        "connect failed: {}",
        last_error()
    );
    let id = open_shell(conn);
    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn, 0, 300) };
    assert_eq!(status, adb::AdbStatus::Ok, "set_io_timeout failed");

    let chunk = vec![0x61u8; 256 * 1024];
    let mut saw_io = false;
    let t0 = Instant::now();
    for _ in 0..256 {
        let status = unsafe { adb::adb_write_channel(conn, id, chunk.as_ptr(), chunk.len()) };
        if status == adb::AdbStatus::Io {
            assert!(
                t0.elapsed().as_secs() < 3,
                "Io arrived too late to be the send timeout: {:?}",
                t0.elapsed()
            );
            saw_io = true;
            break;
        }
        assert_eq!(
            status,
            adb::AdbStatus::Ok,
            "write failed early: {}",
            last_error()
        );
        assert!(t0.elapsed().as_secs() < 5, "writes never blocked");
    }
    assert!(saw_io, "the write timeout never fired");

    let status = unsafe { adb::adb_write_channel(conn, id, chunk.as_ptr(), chunk.len()) };
    assert_eq!(status, adb::AdbStatus::Desynchronized);
    assert!(unsafe { adb::adb_connection_max_payload(conn) } > 0);
    unsafe { adb::adb_connection_free(conn) };
}
