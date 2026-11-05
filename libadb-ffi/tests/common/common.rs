//! A fake adbd on a loopback socket, enough to drive the C entry points
//! through a handshake, one channel and its traffic.

#![allow(dead_code)]

use std::ffi::{c_void, CString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub const CMD_CNXN: u32 = 0x4e58_4e43;
pub const CMD_OPEN: u32 = 0x4e45_504f;
pub const CMD_OKAY: u32 = 0x5941_4b4f;
pub const CMD_WRTE: u32 = 0x4554_5257;
pub const CMD_CLSE: u32 = 0x4553_4c43;
pub const CMD_STLS: u32 = 0x534c_5453;

/// Protocol version that skips payload checksums, so neither side has to
/// compute them.
pub const VERSION: u32 = 0x0100_0001;
/// The one STLS version there is.
pub const STLS_VERSION: u32 = 0x0100_0000;
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

pub fn read_packet<S: Read>(stream: &mut S) -> Option<(u32, u32, Vec<u8>)> {
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

/// A device that answers CNXN with STLS and then only waits for the
/// host to hang up, as one that got no STLS back would.
pub fn fake_adbd_demanding_tls() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (cmd, _, _) = read_packet(&mut stream).expect("the host opens with CNXN");
        assert_eq!(cmd, CMD_CNXN, "the host opens with CNXN");
        stream
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();
        // Whatever follows is not a packet — a host able to answer would
        // send its own STLS and a ClientHello — so it is drained as
        // bytes rather than parsed as a length.
        let mut sink = [0u8; 4096];
        while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    });
    (addr, handle)
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

/// Split a shell_v2 byte stream into `(id, payload)` frames.
pub fn frames(mut stream: &[u8]) -> Vec<(u8, Vec<u8>)> {
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

/// How long a call that is not supposed to hang gets before its test
/// fails.
pub const BOUND: Duration = Duration::from_secs(10);

/// Run `call` on a thread of its own and wait [`BOUND`] for it, so a C
/// call that hangs fails its test instead of hanging the run.
pub fn within<T: Send + 'static>(what: &str, call: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(call());
    });
    match rx.recv_timeout(BOUND) {
        Ok(value) => value,
        Err(e) => panic!("{what} did not finish: {e}"),
    }
}

/// A C handle on its way to another thread, which the C API allows.
/// Take it apart with [`get`](Self::get): a closure naming the field
/// would capture the bare pointer.
pub struct Handle<T>(pub *mut T);

// SAFETY: every handle this carries is one the C API lets threads share.
unsafe impl<T> Send for Handle<T> {}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Handle<T> {}

impl<T> Handle<T> {
    pub fn get(self) -> *mut T {
        self.0
    }
}

/// One packet from the host.
#[derive(Debug)]
pub struct HostPacket {
    pub cmd: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub payload: Vec<u8>,
}

/// A device whose side of the conversation a test writes out, packet by
/// packet: see [`scripted_adbd`].
pub struct Device {
    stream: TcpStream,
    delayed_ack: bool,
}

impl Device {
    /// The next packet from the host, or `None` once it hung up.
    pub fn recv(&mut self) -> Option<HostPacket> {
        let mut h = [0u8; 24];
        self.stream.read_exact(&mut h).ok()?;
        let word = |at: usize| u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
        let mut payload = vec![0u8; word(12) as usize];
        self.stream.read_exact(&mut payload).ok()?;
        Some(HostPacket {
            cmd: word(0),
            arg0: word(4),
            arg1: word(8),
            payload,
        })
    }

    /// The next packet the host sends with command `cmd`; anything
    /// before it is passed over.
    pub fn recv_cmd(&mut self, cmd: u32) -> HostPacket {
        loop {
            let pkt = self.recv().expect("the host hung up");
            if pkt.cmd == cmd {
                return pkt;
            }
        }
    }

    pub fn send(&mut self, cmd: u32, arg0: u32, arg1: u32, payload: &[u8]) {
        self.stream
            .write_all(&header(cmd, arg0, arg1, payload))
            .unwrap();
    }

    /// Answer the host's next OPEN as channel `id`, granting `credit`
    /// under delayed ACK. Returns the host's end of the channel.
    pub fn accept_open(&mut self, id: u32, credit: u32) -> u32 {
        let host = self.recv_cmd(CMD_OPEN).arg0;
        self.okay(id, host, credit);
        host
    }

    /// Acknowledge `len` bytes on channel `id`, an OKAY that carries
    /// them as credit under delayed ACK.
    pub fn okay(&mut self, id: u32, host: u32, len: u32) {
        let credit = len.to_le_bytes();
        let payload: &[u8] = if self.delayed_ack { &credit } else { &[] };
        self.send(CMD_OKAY, id, host, payload);
    }

    /// Take WRTEs on channel `id`, acknowledging each, until `len` bytes
    /// came.
    pub fn take(&mut self, id: u32, host: u32, len: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < len {
            let wrte = self.recv_cmd(CMD_WRTE);
            self.okay(id, host, wrte.payload.len() as u32);
            got.extend_from_slice(&wrte.payload);
        }
        got
    }
}

/// A device on a loopback socket that advertises `features` and leaves
/// everything after the handshake to `script`. It hangs up when the
/// script returns, and the handle gives back what the script did.
pub fn scripted_adbd<T: Send + 'static>(
    features: &'static str,
    script: impl FnOnce(&mut Device) -> T + Send + 'static,
) -> (String, thread::JoinHandle<T>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).unwrap();
        let mut device = Device {
            stream,
            delayed_ack: false,
        };
        let cnxn = device.recv_cmd(CMD_CNXN);
        let wanted = b"delayed_ack";
        device.delayed_ack = features.contains("delayed_ack")
            && cnxn.payload.windows(wanted.len()).any(|w| w == wanted);
        let banner = format!("device::features={features}");
        device.send(CMD_CNXN, VERSION, MAX_PAYLOAD, banner.as_bytes());
        script(&mut device)
    });
    (addr, handle)
}

/// A device that never asks for AUTH leaves this uncalled, but the
/// handshake's API wants one.
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

/// Connect to the device at `addr`, asking for the `features` given.
pub fn connect(addr: &str, features: &str) -> *mut adb::adb_connection_t {
    let uri = CString::new(format!("tcp://{addr}")).unwrap();
    let banner = CString::new(format!("host::features={features}")).unwrap();
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
    conn
}
