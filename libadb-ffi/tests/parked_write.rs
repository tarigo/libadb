//! A write waiting for the device needs no read call running: with
//! nobody else taking packets off the connection it takes them itself,
//! and leaves what it finds for other calls to read. The device here is
//! classic ACK unless a test says otherwise, so every WRTE after the
//! first on a channel waits for an OKAY only a read can receive.

use std::ffi::CString;
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[path = "common/common.rs"]
mod common;
use common::{
    connect, frames, scripted_adbd, within, Handle, BOUND, CMD_CLSE, CMD_OKAY, CMD_OPEN, CMD_WRTE,
    FRAME_LEN, MAX_PAYLOAD,
};

const CLASSIC: &str = "shell_v2";
const DELAYED_ACK: &str = "shell_v2,delayed_ack";
/// Ids the scripts answer OPENs with.
const CH_A: u32 = 1;
const CH_B: u32 = 2;
const CH_C: u32 = 3;
/// `ADB_SHELL_V2_STDIN` and `ADB_SHELL_V2_WINDOW_SIZE_CHANGE` in libadb.h.
const STDIN: u8 = 0;
const WINDOW_SIZE_CHANGE: u8 = 5;
/// What a script gives a write to get to its wait. Nothing fails if the
/// write is later than that; the test just proves less on that run.
const SETTLE: Duration = Duration::from_millis(50);

type Conn = Handle<adb::adb_connection_t>;
type Shell = Handle<adb::adb_shell_t>;

fn open_channel(conn: Conn) -> u64 {
    let dest = b"shell,v2,raw:\0";
    let mut id = 0u64;
    let status = unsafe { adb::adb_open_channel(conn.get(), dest.as_ptr(), dest.len(), &mut id) };
    assert_eq!(status, adb::AdbStatus::Ok, "open failed");
    id
}

fn open_shell(conn: Conn) -> Shell {
    let mut sh = ptr::null_mut();
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
    Handle(sh)
}

fn write(conn: Conn, id: u64, data: &[u8]) -> adb::AdbStatus {
    unsafe { adb::adb_write_channel(conn.get(), id, data.as_ptr(), data.len()) }
}

fn read(conn: Conn, id: u64) -> (adb::AdbStatus, Vec<u8>) {
    let mut buf = [0u8; 64];
    let mut n = 0usize;
    let status =
        unsafe { adb::adb_read_channel(conn.get(), id, buf.as_mut_ptr(), buf.len(), &mut n) };
    (status, buf[..n].to_vec())
}

fn join<T: Send + 'static>(what: &str, handle: thread::JoinHandle<T>) -> T {
    within(what, move || handle.join().unwrap())
}

/// Have the script wait for the test's read to be running. A read on
/// another channel takes this WRTE, answers it and stays in the read,
/// so its OKAY says that read holds the read lock from here on.
fn wait_for_a_read(device: &mut common::Device, ch: u32, host: u32, running: mpsc::Sender<()>) {
    device.send(CMD_WRTE, ch, host, b"ping");
    device.recv_cmd(CMD_OKAY);
    running.send(()).unwrap();
}

#[test]
fn a_shell_opens_with_its_window_size_on_a_classic_device() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let host = d.accept_open(CH_A, 0);
        d.take(CH_A, host, 5 + b"24x80,0x0\0".len())
    });
    let conn = Handle(connect(&addr, CLASSIC));

    let term = CString::new("xterm").unwrap();
    let (status, sh) = within("adb_shell_open", move || {
        let mut sh = ptr::null_mut();
        let status = unsafe {
            adb::adb_shell_open(
                conn.get(),
                ptr::null(),
                0,
                true,
                term.as_ptr(),
                24,
                80,
                &mut sh,
            )
        };
        (status, Handle(sh))
    });
    assert_eq!(status, adb::AdbStatus::Ok);

    let stream = join("the device", device);
    assert_eq!(
        frames(&stream),
        [(WINDOW_SIZE_CHANGE, b"24x80,0x0\0".to_vec())]
    );
    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn.get());
    }
}

/// The caller of a failed open has no handle to clean up with, so the
/// channel is closed here, and the failure reported is the device's.
#[test]
fn a_device_that_closes_during_the_window_size_fails_the_open() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let host = d.accept_open(CH_A, 0);
        d.recv_cmd(CMD_WRTE);
        d.send(CMD_CLSE, CH_A, host, &[]);
        d.recv_cmd(CMD_CLSE)
    });
    let conn = Handle(connect(&addr, CLASSIC));

    let term = CString::new("xterm").unwrap();
    let (status, sh) = within("adb_shell_open", move || {
        let mut sh = ptr::null_mut();
        let status = unsafe {
            adb::adb_shell_open(
                conn.get(),
                ptr::null(),
                0,
                true,
                term.as_ptr(),
                24,
                80,
                &mut sh,
            )
        };
        (status, Handle(sh))
    });
    assert_eq!(status, adb::AdbStatus::ChannelClosed);
    assert!(sh.get().is_null(), "a failed open hands out no handle");

    join("the device", device);
    unsafe { adb::adb_connection_free(conn.get()) };
}

#[test]
fn stdin_goes_out_with_no_read_running() {
    let input = b"echo hi\n";
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let host = d.accept_open(CH_A, 0);
        d.take(CH_A, host, 5 + input.len())
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let sh = open_shell(conn);

    let status = within("adb_shell_write_stdin", move || unsafe {
        adb::adb_shell_write_stdin(sh.get(), input.as_ptr(), input.len())
    });
    assert_eq!(status, adb::AdbStatus::Ok);

    let stream = join("the device", device);
    assert_eq!(frames(&stream), [(STDIN, input.to_vec())]);
    unsafe {
        adb::adb_shell_free(sh.get());
        adb::adb_connection_free(conn.get());
    }
}

#[test]
fn two_writes_in_a_row_finish_on_one_thread() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let host = d.accept_open(CH_A, 0);
        d.take(CH_A, host, b"onetwo".len())
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let id = open_channel(conn);

    let statuses = within("two writes", move || {
        (write(conn, id, b"one"), write(conn, id, b"two"))
    });
    assert_eq!(statuses, (adb::AdbStatus::Ok, adb::AdbStatus::Ok));

    assert_eq!(join("the device", device), b"onetwo");
    unsafe { adb::adb_connection_free(conn.get()) };
}

#[test]
fn one_write_past_max_payload_finishes_alone() {
    let data: Vec<u8> = (0..FRAME_LEN).map(|i| i as u8).collect();
    let expected = data.clone();
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let host = d.accept_open(CH_A, 0);
        d.take(CH_A, host, FRAME_LEN)
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let id = open_channel(conn);

    let status = within("the write", move || write(conn, id, &data));
    assert_eq!(status, adb::AdbStatus::Ok);

    assert_eq!(join("the device", device), expected);
    unsafe { adb::adb_connection_free(conn.get()) };
}

#[test]
fn one_write_past_the_delayed_ack_credit_finishes_alone() {
    const CREDIT: usize = 100;
    let data = vec![0x5A; 10 * CREDIT];
    let expected = data.clone();
    let (addr, device) = scripted_adbd(DELAYED_ACK, |d| {
        let host = d.accept_open(CH_A, CREDIT as u32);
        let mut got = Vec::new();
        while got.len() < 10 * CREDIT {
            let wrte = d.recv_cmd(CMD_WRTE);
            assert!(wrte.payload.len() <= CREDIT, "sent past the credit");
            d.okay(CH_A, host, wrte.payload.len() as u32);
            got.extend_from_slice(&wrte.payload);
        }
        got
    });
    let conn = Handle(connect(&addr, DELAYED_ACK));
    assert!(unsafe { adb::adb_connection_delayed_ack(conn.get()) });
    let id = open_channel(conn);

    let status = within("the write", move || write(conn, id, &data));
    assert_eq!(status, adb::AdbStatus::Ok);

    assert_eq!(join("the device", device), expected);
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// The write that finishes last has no other call left to read for it,
/// and the one reading until then gets no word that it may stop.
#[test]
fn writes_on_two_channels_finish_with_no_read_running() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let a = d.accept_open(CH_A, 0);
        let b = d.accept_open(CH_B, 0);
        let mut bytes = [0; 2];
        while bytes != [FRAME_LEN, 2 * FRAME_LEN] {
            let wrte = d.recv_cmd(CMD_WRTE);
            let (index, host) = if wrte.arg0 == a { (0, a) } else { (1, b) };
            bytes[index] += wrte.payload.len();
            d.okay(CH_A + index as u32, host, 0);
        }
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let a = open_channel(conn);
    let b = open_channel(conn);

    let other = thread::spawn(move || write(conn, a, &[0xAA; FRAME_LEN]));
    let status = within("the write", move || write(conn, b, &[0xBB; 2 * FRAME_LEN]));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(join("the other write", other), adb::AdbStatus::Ok);

    join("the device", device);
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// Chunks of the two may interleave, as they do on a socket, but all of
/// both arrive: the writers take turns at the one credit and at reading
/// for it.
#[test]
fn writes_on_one_channel_finish_with_no_read_running() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let host = d.accept_open(CH_A, 0);
        d.take(CH_A, host, 2 * FRAME_LEN)
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let id = open_channel(conn);

    let other = thread::spawn(move || write(conn, id, &[0xAA; FRAME_LEN]));
    let status = within("the write", move || write(conn, id, &[0xBB; FRAME_LEN]));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(join("the other write", other), adb::AdbStatus::Ok);

    let got = join("the device", device);
    for byte in [0xAA, 0xBB] {
        let count = got.iter().filter(|&&b| b == byte).count();
        assert_eq!(count, FRAME_LEN, "bytes of {byte:#x}");
    }
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// A write held up by the transport has no packet to wait for, so a
/// read begun for it would block for nothing. With the first write stuck
/// in a full socket mid-packet, the second waits for the write half, and
/// under delayed ACK all it needs once that comes free is to be polled.
#[test]
fn a_write_held_up_by_the_transport_does_not_start_a_read() {
    /// Past what the socket buffers hold, however far they grow.
    const LOTS: usize = 16 * 1024 * 1024;
    let (full_tx, full) = mpsc::channel::<()>();
    let (addr, device) = scripted_adbd(DELAYED_ACK, move |d| {
        d.accept_open(CH_A, 1 << 30);
        d.accept_open(CH_B, 1 << 30);
        full.recv().unwrap();
        let mut bytes = 0;
        while bytes < LOTS + 3 {
            bytes += d.recv_cmd(CMD_WRTE).payload.len();
        }
    });
    let conn = Handle(connect(&addr, DELAYED_ACK));
    let a = open_channel(conn);
    let b = open_channel(conn);

    let lots = vec![0x5A; LOTS];
    let stuck = thread::spawn(move || write(conn, a, &lots));
    thread::sleep(4 * SETTLE);
    let waiting = thread::spawn(move || write(conn, b, b"two"));
    thread::sleep(SETTLE);
    full_tx.send(()).unwrap();

    assert_eq!(join("the stuck write", stuck), adb::AdbStatus::Ok);
    assert_eq!(join("the waiting write", waiting), adb::AdbStatus::Ok);
    join("the device", device);
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// Both ways at once, as a command echoing its stdin: the write and the
/// read keep taking the lock from each other, and neither may be left
/// waiting for the other.
fn echo_both_ways(features: &'static str) {
    const TOTAL: usize = 16 * FRAME_LEN;
    let (addr, device) = scripted_adbd(features, |d| {
        let host = d.accept_open(CH_A, FRAME_LEN as u32);
        let mut echoed = 0;
        while echoed < TOTAL {
            let wrte = d.recv_cmd(CMD_WRTE);
            echoed += wrte.payload.len();
            d.okay(CH_A, host, wrte.payload.len() as u32);
            d.send(CMD_WRTE, CH_A, host, &wrte.payload);
        }
        while d.recv().is_some() {}
    });
    let conn = Handle(connect(&addr, features));
    let id = open_channel(conn);

    let reading = thread::spawn(move || {
        let mut got = 0;
        while got < TOTAL {
            let (status, data) = read(conn, id);
            assert_eq!(status, adb::AdbStatus::Ok);
            got += data.len();
        }
    });
    let writing = thread::spawn(move || {
        for _ in 0..TOTAL / 4096 {
            assert_eq!(write(conn, id, &[0x5A; 4096]), adb::AdbStatus::Ok);
        }
    });

    join("the writes", writing);
    join("the reads", reading);
    unsafe { adb::adb_connection_free(conn.get()) };
    join("the device", device);
}

#[test]
fn writing_and_reading_at_once_keep_moving() {
    echo_both_ways(CLASSIC);
}

#[test]
fn writing_and_reading_at_once_keep_moving_under_delayed_ack() {
    echo_both_ways(DELAYED_ACK);
}

#[test]
fn what_arrives_during_a_write_is_kept_for_those_it_is_for() {
    let data = vec![0x42; 3 * MAX_PAYLOAD as usize];
    let expected = data.clone();
    let (addr, device) = scripted_adbd(CLASSIC, move |d| {
        let a = d.accept_open(CH_A, 0);
        let b = d.accept_open(CH_B, 0);

        // Ahead of the OKAY the write is waiting for.
        let mut got = d.recv_cmd(CMD_WRTE).payload;
        d.send(CMD_WRTE, CH_B, b, b"for-b");
        d.send(CMD_OPEN, 500, 0, b"tcp:7000\0");
        d.okay(CH_A, a, 0);

        let mut okays_on_b = 0;
        let mut refused = false;
        while let Some(pkt) = d.recv() {
            match pkt.cmd {
                CMD_WRTE if pkt.arg1 == CH_A => {
                    got.extend_from_slice(&pkt.payload);
                    d.okay(CH_A, a, 0);
                }
                CMD_OKAY if pkt.arg1 == CH_B => okays_on_b += 1,
                CMD_CLSE if pkt.arg1 == 500 => refused = true,
                _ => {}
            }
        }
        (got, okays_on_b, refused)
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let a = open_channel(conn);
    let b = open_channel(conn);

    let status = within("the write", move || write(conn, a, &data));
    assert_eq!(status, adb::AdbStatus::Ok);

    let (status, got) = within("the read", move || read(conn, b));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"for-b");

    let (status, dest) = within("the accept", move || {
        let mut dest = [0u8; 32];
        let mut len = 0usize;
        let status =
            unsafe { adb::adb_accept_channel(conn.get(), dest.as_mut_ptr(), dest.len(), &mut len) };
        (status, dest[..len].to_vec())
    });
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(dest, b"tcp:7000\0");

    unsafe { adb::adb_connection_free(conn.get()) };
    let (got, okays_on_b, refused) = join("the device", device);
    assert_eq!(got, expected);
    assert_eq!(okays_on_b, 1, "the data for the other channel was answered");
    assert!(!refused, "the OPEN waited for its accept");
}

/// This is what `TICK` is for. The read lock is taken while the write
/// parks, so the write cannot read for itself. The read holding the
/// lock returns to C without having taken the OKAY, so nothing wakes
/// the write: it has to look again.
#[test]
fn a_write_outlives_the_read_that_kept_it_from_reading() {
    let (running_tx, running) = mpsc::channel();
    let (returned, returned_rx) = mpsc::channel::<()>();
    let (addr, device) = scripted_adbd(CLASSIC, move |d| {
        let a = d.accept_open(CH_A, 0);
        let b = d.accept_open(CH_B, 0);
        wait_for_a_read(d, CH_A, a, running_tx);

        d.recv_cmd(CMD_WRTE);
        thread::sleep(SETTLE);
        d.send(CMD_WRTE, CH_B, b, b"for-b");
        returned_rx.recv().unwrap();
        thread::sleep(SETTLE);
        d.okay(CH_A, a, 0);
        d.take(CH_A, a, b"two".len())
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let a = open_channel(conn);
    let b = open_channel(conn);

    let reading = thread::spawn(move || read(conn, b));
    running.recv_timeout(BOUND).expect("the read never started");

    let writing = thread::spawn(move || (write(conn, a, b"one"), write(conn, a, b"two")));

    let (status, got) = join("the read", reading);
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"for-b");
    returned.send(()).unwrap();

    let statuses = join("the writes", writing);
    assert_eq!(statuses, (adb::AdbStatus::Ok, adb::AdbStatus::Ok));

    assert_eq!(join("the device", device), b"two");
    unsafe { adb::adb_connection_free(conn.get()) };
}

#[test]
fn a_hangup_ends_a_parked_write() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        d.accept_open(CH_A, 0);
        d.recv_cmd(CMD_WRTE);
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let id = open_channel(conn);

    let statuses = within("two writes", move || {
        (write(conn, id, b"one"), write(conn, id, b"two"))
    });
    assert_eq!(statuses, (adb::AdbStatus::Ok, adb::AdbStatus::Io));

    join("the device", device);
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// The read gets the error and returns it to C. The write behind it
/// gets `Disconnected`, the status for a connection that ended: it saw
/// nothing fail itself.
#[test]
fn a_hangup_that_ends_the_read_also_ends_the_write_behind_it() {
    let (running_tx, running) = mpsc::channel();
    let (addr, device) = scripted_adbd(CLASSIC, move |d| {
        let a = d.accept_open(CH_A, 0);
        d.accept_open(CH_B, 0);
        wait_for_a_read(d, CH_A, a, running_tx);

        d.recv_cmd(CMD_WRTE);
        thread::sleep(SETTLE);
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let a = open_channel(conn);
    let b = open_channel(conn);

    let reading = thread::spawn(move || read(conn, b));
    running.recv_timeout(BOUND).expect("the read never started");

    let statuses = within("two writes", move || {
        (write(conn, a, b"one"), write(conn, a, b"two"))
    });
    assert_eq!(statuses, (adb::AdbStatus::Ok, adb::AdbStatus::Disconnected));

    let (status, _) = join("the read", reading);
    assert_eq!(status, adb::AdbStatus::Io);
    join("the device", device);
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// The timeout reaches the write through its own read. The OKAY that
/// comes after it is not lost: what a timed-out read leaves stays on
/// the socket for the next one.
#[test]
fn a_read_timeout_ends_a_parked_write_and_the_connection_goes_on() {
    let (timed_out, timed_out_rx) = mpsc::channel::<()>();
    let (addr, device) = scripted_adbd(CLASSIC, move |d| {
        let host = d.accept_open(CH_A, 0);
        d.recv_cmd(CMD_WRTE);
        timed_out_rx.recv().unwrap();
        d.okay(CH_A, host, 0);
        d.take(CH_A, host, b"two".len())
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let id = open_channel(conn);
    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn.get(), 100, 0) };
    assert_eq!(status, adb::AdbStatus::Ok);

    let status = within("the first write", move || write(conn, id, b"one"));
    assert_eq!(status, adb::AdbStatus::Ok);

    let t0 = Instant::now();
    let status = within("the parked write", move || write(conn, id, b"two"));
    assert_eq!(status, adb::AdbStatus::Io);
    assert!(
        t0.elapsed() >= Duration::from_millis(100),
        "failed before the timeout could fire: {:?}",
        t0.elapsed()
    );

    let status = unsafe { adb::adb_connection_set_io_timeout_ms(conn.get(), 0, 0) };
    assert_eq!(status, adb::AdbStatus::Ok);
    timed_out.send(()).unwrap();
    let status = within("the write after it", move || write(conn, id, b"two"));
    assert_eq!(status, adb::AdbStatus::Ok);

    assert_eq!(join("the device", device), b"two");
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// A command stuck on its stdout stops taking stdin, so the device
/// gives the write no credit until the host has read that output. The
/// write is already reading, holding the lock, when the read comes, and
/// neither would ever move if the read waited for the lock.
#[test]
fn a_read_gets_past_a_write_that_holds_the_read_lock() {
    let (addr, device) = scripted_adbd(DELAYED_ACK, |d| {
        let host = d.accept_open(CH_A, 1);
        d.recv_cmd(CMD_WRTE);
        d.send(CMD_WRTE, CH_A, host, b"output");
        let credit = d.recv_cmd(CMD_OKAY);
        assert_eq!(credit.payload, 6u32.to_le_bytes());
        d.okay(CH_A, host, 1);
        d.take(CH_A, host, 1)
    });
    let conn = Handle(connect(&addr, DELAYED_ACK));
    let id = open_channel(conn);

    let writing = thread::spawn(move || write(conn, id, b"xy"));
    thread::sleep(SETTLE);

    let (status, got) = within("the read", move || read(conn, id));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"output");

    assert_eq!(join("the write", writing), adb::AdbStatus::Ok);
    assert_eq!(join("the device", device), b"y");
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// The same with the read waiting first, for data the write has yet to
/// receive.
#[test]
fn a_read_gets_what_a_write_takes_in_while_it_waits() {
    let (reading_tx, reading) = mpsc::channel::<()>();
    let (addr, device) = scripted_adbd(DELAYED_ACK, move |d| {
        let host = d.accept_open(CH_A, 1);
        d.recv_cmd(CMD_WRTE);
        reading.recv().unwrap();
        thread::sleep(SETTLE);
        d.send(CMD_WRTE, CH_A, host, b"output");
        let credit = d.recv_cmd(CMD_OKAY);
        assert_eq!(credit.payload, 6u32.to_le_bytes());
        d.okay(CH_A, host, 1);
        d.take(CH_A, host, 1)
    });
    let conn = Handle(connect(&addr, DELAYED_ACK));
    let id = open_channel(conn);

    let writing = thread::spawn(move || write(conn, id, b"xy"));
    thread::sleep(SETTLE);
    reading_tx.send(()).unwrap();

    let (status, got) = within("the read", move || read(conn, id));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"output");

    assert_eq!(join("the write", writing), adb::AdbStatus::Ok);
    assert_eq!(join("the device", device), b"y");
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// A read kept off the lock by a write has to take over the moment the
/// write is done: no call is left to read for it.
#[test]
fn a_read_takes_over_from_a_write_that_finished() {
    let (addr, device) = scripted_adbd(CLASSIC, |d| {
        let a = d.accept_open(CH_A, 0);
        let b = d.accept_open(CH_B, 0);
        d.recv_cmd(CMD_WRTE);
        thread::sleep(2 * SETTLE);
        d.okay(CH_A, a, 0);
        let got = d.take(CH_A, a, b"two".len());
        thread::sleep(SETTLE);
        d.send(CMD_WRTE, CH_B, b, b"for-b");
        while d.recv_cmd(CMD_OKAY).arg1 != CH_B {}
        got
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let a = open_channel(conn);
    let b = open_channel(conn);

    let writing = thread::spawn(move || (write(conn, a, b"one"), write(conn, a, b"two")));
    thread::sleep(SETTLE);

    let (status, got) = within("the read", move || read(conn, b));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"for-b");

    let statuses = join("the writes", writing);
    assert_eq!(statuses, (adb::AdbStatus::Ok, adb::AdbStatus::Ok));
    assert_eq!(join("the device", device), b"two");
    unsafe { adb::adb_connection_free(conn.get()) };
}

/// Two reads are no different: the second returns while the first is
/// still blocked, rather than wait on the first read's data.
#[test]
fn a_read_gets_what_the_read_holding_the_lock_takes_in() {
    let (running_tx, running) = mpsc::channel();
    let (returned, returned_rx) = mpsc::channel::<()>();
    let (addr, device) = scripted_adbd(CLASSIC, move |d| {
        let a = d.accept_open(CH_A, 0);
        let b = d.accept_open(CH_B, 0);
        let c = d.accept_open(CH_C, 0);
        wait_for_a_read(d, CH_C, c, running_tx);

        thread::sleep(SETTLE);
        d.send(CMD_WRTE, CH_B, b, b"for-b");
        returned_rx.recv().unwrap();
        d.send(CMD_WRTE, CH_A, a, b"for-a");
        while d.recv_cmd(CMD_OKAY).arg1 != CH_A {}
    });
    let conn = Handle(connect(&addr, CLASSIC));
    let a = open_channel(conn);
    let b = open_channel(conn);
    let _c = open_channel(conn);

    let first = thread::spawn(move || read(conn, a));
    running.recv_timeout(BOUND).expect("the read never started");

    let (status, got) = within("the second read", move || read(conn, b));
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"for-b");
    assert!(!first.is_finished(), "the first read has nothing yet");
    returned.send(()).unwrap();

    let (status, got) = join("the first read", first);
    assert_eq!(status, adb::AdbStatus::Ok);
    assert_eq!(got, b"for-a");
    join("the device", device);
    unsafe { adb::adb_connection_free(conn.get()) };
}
