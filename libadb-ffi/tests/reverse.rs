//! The reverse/accept C API: accept a channel the device opens toward
//! the host, then exchange bytes over it. A minimal raw device drives
//! the wire directly.

use std::ffi::{c_void, CString};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::ptr;

#[path = "common/common.rs"]
mod common;
use common::{header, CMD_CNXN, CMD_OKAY, CMD_WRTE, MAX_PAYLOAD, VERSION};

const CMD_OPEN: u32 = 0x4e45_504f;
const CMD_CLSE: u32 = 0x4553_4c43;

unsafe extern "C" fn never_signs(
    _u: *mut c_void,
    _t: *const u8,
    _tl: usize,
    _o: *mut u8,
    _oc: usize,
    _ol: *mut usize,
) -> adb::AdbStatus {
    adb::AdbStatus::Auth
}

fn recv_pkt(s: &mut TcpStream) -> Option<(u32, u32, u32, Vec<u8>)> {
    let mut h = [0u8; 24];
    s.read_exact(&mut h).ok()?;
    let cmd = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let arg0 = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    let arg1 = u32::from_le_bytes([h[8], h[9], h[10], h[11]]);
    let len = u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        s.read_exact(&mut payload).ok()?;
    }
    Some((cmd, arg0, arg1, payload))
}

/// Handshake, then immediately open one channel toward the host
/// (device id 500, destination `tcp:7000`). After the host's READY,
/// echo the first WRTE with an `echo:` prefix, then close.
fn opening_adbd() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let device = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();

        // Handshake.
        let (_c, _a0, _a1, _p) = recv_pkt(&mut s).unwrap(); // CNXN
        s.write_all(&header(
            CMD_CNXN,
            VERSION,
            MAX_PAYLOAD,
            b"device::features=shell_v2,delayed_ack",
        ))
        .unwrap();

        // Open a channel toward the host: device local id 500, credit
        // in arg1 (delayed ack), destination tcp:7000.
        s.write_all(&header(CMD_OPEN, 500, 4096, b"tcp:7000\0"))
            .unwrap();

        // The host answers READY(host_id, 500, credit) on accept.
        let (cmd, host_id, mine, _credit) = recv_pkt(&mut s).unwrap();
        assert_eq!(cmd, CMD_OKAY, "expected READY for our OPEN");
        assert_eq!(mine, 500, "READY names our local id");

        // The host's WRTE (its data on the channel): ack + echo back.
        let (cmd, _a0, _a1, data) = recv_pkt(&mut s).unwrap();
        assert_eq!(cmd, CMD_WRTE);
        // delayed-ack: every OKAY carries a credit refill.
        s.write_all(&header(CMD_OKAY, 500, host_id, &1000u32.to_le_bytes()))
            .unwrap();
        let mut echo = b"echo:".to_vec();
        echo.extend_from_slice(&data);
        s.write_all(&header(CMD_WRTE, 500, host_id, &echo)).unwrap();
        // Consume the host's ack for our echo, then idle.
        let _ = recv_pkt(&mut s);
    });
    (addr, device)
}

#[test]
fn accept_an_opened_channel_and_exchange() {
    let (addr, device) = opening_adbd();
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
    let st = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(st, adb::AdbStatus::Ok, "connect");

    let mut dest = [0u8; 64];
    let mut dest_len = 0usize;
    let st = unsafe { adb::adb_accept_channel(conn, dest.as_mut_ptr(), dest.len(), &mut dest_len) };
    assert_eq!(st, adb::AdbStatus::Ok, "accept_channel");
    assert_eq!(&dest[..dest_len], b"tcp:7000\0", "destination reported");

    let mut id = 0u64;
    let st = unsafe { adb::adb_incoming_accept(conn, &mut id) };
    assert_eq!(st, adb::AdbStatus::Ok, "incoming_accept");

    let st = unsafe { adb::adb_write_channel(conn, id, b"hi".as_ptr(), 2) };
    assert_eq!(st, adb::AdbStatus::Ok, "write");

    let mut buf = [0u8; 32];
    let mut n = 0usize;
    let st = unsafe { adb::adb_read_channel(conn, id, buf.as_mut_ptr(), buf.len(), &mut n) };
    assert_eq!(st, adb::AdbStatus::Ok, "read");
    assert_eq!(&buf[..n], b"echo:hi");

    device
        .join()
        .expect("the fake device saw the exchange it expected");
    unsafe { adb::adb_connection_free(conn) };
}

/// Serve one `reverse:` service channel: expect the host's OPEN for
/// `expected_dest`, answer READY, push `reply` in one WRTE, then close
/// — consuming the host's ack and its answering CLSE on the way.
fn serve_service(s: &mut TcpStream, dev_id: u32, expected_dest: &[u8], reply: &[u8]) {
    let (cmd, host_id, _a1, payload) = recv_pkt(s).unwrap();
    assert_eq!(cmd, CMD_OPEN, "expected the service OPEN");
    assert_eq!(payload, expected_dest, "service destination");
    s.write_all(&header(CMD_OKAY, dev_id, host_id, &[]))
        .unwrap();
    s.write_all(&header(CMD_WRTE, dev_id, host_id, reply))
        .unwrap();
    let (cmd, _, _, _) = recv_pkt(s).unwrap();
    assert_eq!(cmd, CMD_OKAY, "expected the host's ack");
    s.write_all(&header(CMD_CLSE, dev_id, host_id, &[]))
        .unwrap();
    let (cmd, _, _, _) = recv_pkt(s).unwrap();
    assert_eq!(cmd, CMD_CLSE, "expected the host to free the channel");
}

/// A device answering the whole rule-service conversation the test
/// below drives, in the exact frames a real adbd was probed to send.
fn rule_service_adbd() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let device = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();

        let _ = recv_pkt(&mut s).unwrap(); // CNXN
        s.write_all(&header(
            CMD_CNXN,
            VERSION,
            MAX_PAYLOAD,
            b"device::features=shell_v2",
        ))
        .unwrap();

        serve_service(
            &mut s,
            700,
            b"reverse:forward:tcp:0;tcp:6200\0",
            b"OKAY000538547",
        );
        serve_service(
            &mut s,
            701,
            b"reverse:forward:tcp:0;tcp:6201\0",
            b"OKAY000538548",
        );
        serve_service(
            &mut s,
            702,
            b"reverse:list-forward\0",
            b"001ahost-19 tcp:6100 tcp:6100\n",
        );
        serve_service(&mut s, 703, b"reverse:killforward:tcp:6100\0", b"OKAY");
        serve_service(&mut s, 704, b"reverse:killforward-all\0", b"OKAY");
    });
    (addr, device)
}

#[test]
fn reverse_rules_flow_through_the_split_adapter() {
    let (addr, device_thread) = rule_service_adbd();
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
    let st = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(st, adb::AdbStatus::Ok, "connect");

    let device = CString::new("tcp:0").unwrap();
    let host = CString::new("tcp:6200").unwrap();
    let mut data = [0u8; 64];
    let mut len = 0usize;
    let st = unsafe {
        adb::adb_reverse_forward(
            conn,
            device.as_ptr(),
            host.as_ptr(),
            data.as_mut_ptr(),
            data.len(),
            &mut len,
        )
    };
    assert_eq!(st, adb::AdbStatus::Ok, "reverse_forward");
    assert_eq!(&data[..len], b"38547", "the bound port comes back");

    // Truncate-and-report: a 2-byte buffer still learns the full size.
    let host = CString::new("tcp:6201").unwrap();
    let mut tiny = [0u8; 2];
    let mut len = 0usize;
    let st = unsafe {
        adb::adb_reverse_forward(
            conn,
            device.as_ptr(),
            host.as_ptr(),
            tiny.as_mut_ptr(),
            tiny.len(),
            &mut len,
        )
    };
    assert_eq!(st, adb::AdbStatus::Ok, "truncated reverse_forward");
    assert_eq!(len, 5, "full length reported despite the short buffer");
    assert_eq!(&tiny, b"38", "the truncated prefix is written");

    let mut listing = [0u8; 128];
    let mut len = 0usize;
    let st = unsafe { adb::adb_reverse_list(conn, listing.as_mut_ptr(), listing.len(), &mut len) };
    assert_eq!(st, adb::AdbStatus::Ok, "reverse_list");
    assert_eq!(&listing[..len], b"host-19 tcp:6100 tcp:6100\n");

    let rule = CString::new("tcp:6100").unwrap();
    let st = unsafe { adb::adb_reverse_remove(conn, rule.as_ptr()) };
    assert_eq!(st, adb::AdbStatus::Ok, "reverse_remove");

    let st = unsafe { adb::adb_reverse_remove_all(conn) };
    assert_eq!(st, adb::AdbStatus::Ok, "reverse_remove_all");

    device_thread
        .join()
        .expect("the fake device saw every frame it expected");
    unsafe { adb::adb_connection_free(conn) };
}

/// Two OPENs land before the host looks: reporting is idempotent on
/// the staged request (800 until its verdict), and each verdict
/// answers exactly the staged one — 800 rejected, then 801 accepted.
fn two_opens_adbd() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let device = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();

        let _ = recv_pkt(&mut s).unwrap(); // CNXN
        s.write_all(&header(
            CMD_CNXN,
            VERSION,
            MAX_PAYLOAD,
            b"device::features=shell_v2",
        ))
        .unwrap();

        s.write_all(&header(CMD_OPEN, 800, 0, b"tcp:7100\0"))
            .unwrap();
        s.write_all(&header(CMD_OPEN, 801, 0, b"tcp:7200\0"))
            .unwrap();

        // The verdicts, in the order the host hands them down: CLSE
        // for the rejected 800, then READY for the accepted 801.
        let (cmd, _a0, mine, _p) = recv_pkt(&mut s).unwrap();
        assert_eq!(cmd, CMD_CLSE, "expected CLSE for the rejected request");
        assert_eq!(mine, 800, "the reject must answer the staged OPEN");
        let (cmd, _host_id, mine, _p) = recv_pkt(&mut s).unwrap();
        assert_eq!(cmd, CMD_OKAY, "expected READY for the staged request");
        assert_eq!(mine, 801, "the verdict must answer the staged OPEN");
    });
    (addr, device)
}

#[test]
fn a_verdict_answers_the_reported_request() {
    let (addr, device) = two_opens_adbd();
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
    let st = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(st, adb::AdbStatus::Ok, "connect");

    // Truncate-and-report on the staged request: probe the length with
    // no buffer first, then fetch the bytes — the same request twice.
    let mut len = 0usize;
    let st = unsafe { adb::adb_accept_channel(conn, ptr::null_mut(), 0, &mut len) };
    assert_eq!(st, adb::AdbStatus::Ok, "length probe");
    assert_eq!(len, b"tcp:7100\0".len(), "full length reported");

    let mut dest = [0u8; 32];
    let st = unsafe { adb::adb_accept_channel(conn, dest.as_mut_ptr(), dest.len(), &mut len) };
    assert_eq!(st, adb::AdbStatus::Ok, "repeated report");
    assert_eq!(
        &dest[..len],
        b"tcp:7100\0",
        "a repeated report answers with the staged request, not the next one"
    );

    // The verdict consumes the staged request — the device asserts the
    // CLSE names 800, not whatever sits at the queue's head.
    let st = unsafe { adb::adb_incoming_reject(conn) };
    assert_eq!(st, adb::AdbStatus::Ok, "reject the staged request");

    // Only now does reporting move on to the second OPEN.
    let st = unsafe { adb::adb_accept_channel(conn, dest.as_mut_ptr(), dest.len(), &mut len) };
    assert_eq!(st, adb::AdbStatus::Ok, "next report");
    assert_eq!(
        &dest[..len],
        b"tcp:7200\0",
        "the next OPEN follows the verdict"
    );
    let mut id = 0u64;
    let st = unsafe { adb::adb_incoming_accept(conn, &mut id) };
    assert_eq!(st, adb::AdbStatus::Ok, "accept the staged request");

    // Nothing is staged any more.
    let st = unsafe { adb::adb_incoming_reject(conn) };
    assert_eq!(
        st,
        adb::AdbStatus::InvalidArg,
        "the verdict consumed the stage"
    );

    device
        .join()
        .expect("the fake device saw the verdicts it expected");
    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn a_device_refusal_surfaces_as_adb_err_reverse() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let device = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();
        let _ = recv_pkt(&mut s).unwrap(); // CNXN
        s.write_all(&header(
            CMD_CNXN,
            VERSION,
            MAX_PAYLOAD,
            b"device::features=shell_v2",
        ))
        .unwrap();
        serve_service(
            &mut s,
            705,
            b"reverse:forward:garbage;tcp:1\0",
            b"FAIL0014bad forward: garbage",
        );
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
    let st = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(st, adb::AdbStatus::Ok, "connect");

    let device_spec = CString::new("garbage").unwrap();
    let host_spec = CString::new("tcp:1").unwrap();
    let st = unsafe {
        adb::adb_reverse_forward(
            conn,
            device_spec.as_ptr(),
            host_spec.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    assert_eq!(
        st,
        adb::AdbStatus::Reverse,
        "a device refusal is its own status, not an internal error"
    );
    let msg = unsafe { std::ffi::CStr::from_ptr(adb::adb_last_error()) };
    assert!(
        msg.to_string_lossy().contains("bad forward: garbage"),
        "the device's message reaches the caller: {msg:?}"
    );

    device.join().expect("the fake device saw the exchange");
    unsafe { adb::adb_connection_free(conn) };
}

#[test]
fn reject_before_any_accept_is_an_error() {
    // No pending request: reject and accept both complain rather than
    // block or panic.
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_nodelay(true).unwrap();
            let _ = recv_pkt(&mut s);
            let _ = s.write_all(&header(
                CMD_CNXN,
                VERSION,
                MAX_PAYLOAD,
                b"device::features=shell_v2",
            ));
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        addr
    };
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
    let st = unsafe {
        adb::adb_connect_with_authenticator(uri.as_ptr(), &auth, banner.as_ptr(), &mut conn)
    };
    assert_eq!(st, adb::AdbStatus::Ok, "connect");

    let st = unsafe { adb::adb_incoming_reject(conn) };
    assert_eq!(
        st,
        adb::AdbStatus::InvalidArg,
        "reject with nothing pending"
    );

    unsafe { adb::adb_connection_free(conn) };
}
