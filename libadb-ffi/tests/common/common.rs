//! A fake adbd on a loopback socket, enough to drive the C entry points
//! through a handshake, one channel and its traffic.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

pub const CMD_CNXN: u32 = 0x4e58_4e43;
pub const CMD_OPEN: u32 = 0x4e45_504f;
pub const CMD_OKAY: u32 = 0x5941_4b4f;
pub const CMD_WRTE: u32 = 0x4554_5257;
pub const CMD_CLSE: u32 = 0x4553_4c43;

/// Protocol version that skips payload checksums, so neither side has to
/// compute them.
pub const VERSION: u32 = 0x0100_0001;
/// Small enough that a frame has to be split across many WRTEs, which
/// is where interleaving shows up.
pub const MAX_PAYLOAD: u32 = 1024;
pub const FRAME_LEN: usize = 16 * 1024;

pub fn header(cmd: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Vec<u8> {
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

pub fn read_packet(stream: &mut TcpStream) -> Option<(u32, u32, Vec<u8>)> {
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
/// parked in the middle of its first frame — the moment a second
/// sender must enter for the two to contend. It carries a confirmation
/// sender: the device holds the parking ack until the test confirms
/// through it that the second sender is entering its write.
pub fn fake_adbd() -> (
    String,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<mpsc::Sender<()>>,
) {
    fake_adbd_pushing(Vec::new())
}

/// The same, except it writes `pushes` into the channel as soon as it
/// is open — one WRTE per entry.
pub fn fake_adbd_pushing(
    pushes: Vec<Vec<u8>>,
) -> (
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
        // The tests pace themselves by acknowledgement round-trips;
        // without this, Nagle turns each of them into a 40 ms stall.
        stream.set_nodelay(true).unwrap();
        let mut channel_stream = Vec::new();
        let mut remote_id = 0u32;
        let mut wrte_seen = 0u32;
        let mut delayed_ack = false;

        while let Some((cmd, arg0, payload)) = read_packet(&mut stream) {
            if std::env::var_os("FAKE_ADBD_TRACE").is_some() {
                eprintln!("dev <- {cmd:08x} arg0={arg0} len={}", payload.len());
            }
            match cmd {
                CMD_CNXN => {
                    // The device advertises delayed_ack, so the mode is
                    // the host banner's choice: negotiation needs both.
                    let feature = b"delayed_ack";
                    delayed_ack = payload.windows(feature.len()).any(|w| w == feature);
                    let banner = b"device::features=shell_v2,delayed_ack";
                    stream
                        .write_all(&header(CMD_CNXN, VERSION, MAX_PAYLOAD, banner))
                        .unwrap();
                }
                CMD_OPEN => {
                    remote_id = arg0;
                    if delayed_ack {
                        // In delayed-ACK mode the OKAY that answers OPEN
                        // carries the writer's initial budget.
                        let budget = 1_000_000u32.to_le_bytes();
                        stream
                            .write_all(&header(CMD_OKAY, 1, remote_id, &budget))
                            .unwrap();
                    } else {
                        stream
                            .write_all(&header(CMD_OKAY, 1, remote_id, &[]))
                            .unwrap();
                    }
                    for push in &pushes {
                        stream
                            .write_all(&header(CMD_WRTE, 1, remote_id, push))
                            .unwrap();
                    }
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
