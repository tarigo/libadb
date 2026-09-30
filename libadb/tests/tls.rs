//! The TLS transport against a real `rustls` server.
//!
//! The device side here is deliberately written in a different style
//! from the client under test: blocking, on its own thread, over
//! `rustls`' own blocking stream. An oracle that reuses the code it is
//! checking proves nothing.

#![cfg(all(feature = "tls", any(feature = "tokio", feature = "smol")))]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;

use embedded_io_async::{Read, Write};
use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{cert, AdbKey};
use libadb::tls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use libadb::tls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use libadb::tls::rustls::{DistinguishedName, ServerConfig, ServerConnection, StreamOwned};
use libadb::tls::{rustls, TlsClientConfig, TlsIdentity};
use libadb::transport::common::Transport;
use libadb::transport::tls::{MaybeTls, StartTls, TlsError};
use libadb::Splittable;

#[path = "common/common.rs"]
mod common;

#[path = "fake_device/fake_device.rs"]
mod fake_device;

#[path = "rt/rt.rs"]
mod rt;

#[path = "test_key/test_key.rs"]
mod test_key;

/// What the fake device does with the certificate the host offers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyPolicy {
    /// Take any client certificate, the way a device that already
    /// trusts the key does.
    Accept,
    /// Refuse it. In TLS 1.3 the client's handshake still completes and
    /// the alert only reaches it on the first read.
    Reject,
}

fn host_key() -> AdbKey {
    AdbKey::from_pkcs8_pem(test_key::PKCS8_PEM, &mut OsRng, test_key::NAME).unwrap()
}

/// A device certificate, freshly minted. Wireless debugging does the
/// same: the pairing server generates one per run.
fn device_identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = AdbKey::generate(&mut OsRng, "device@fake").unwrap();
    let der = cert::build(&key, &mut OsRng).unwrap();
    let pkcs8 = key.to_pkcs8_der().unwrap();
    (
        CertificateDer::from(der),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec())),
    )
}

#[derive(Debug)]
struct ClientPolicy {
    accept: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// How many client certificates the device has been shown.
    shown: Arc<AtomicUsize>,
}

impl ClientCertVerifier for ClientPolicy {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.shown.fetch_add(1, Ordering::Relaxed);
        if self.accept {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The device's side of TLS 1.3, taking or refusing the host's key.
fn device_config(policy: KeyPolicy) -> Arc<ServerConfig> {
    device_config_counting(policy, Arc::default())
}

/// [`device_config`], counting in `shown` the certificates it checks.
fn device_config_counting(policy: KeyPolicy, shown: Arc<AtomicUsize>) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (cert, key) = device_identity();
    let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(ClientPolicy {
            accept: policy == KeyPolicy::Accept,
            provider,
            shown,
        }))
        .with_single_cert(vec![cert], key)
        .unwrap();
    Arc::new(config)
}

/// What the fake device did, so a test can check the host's side of it.
struct DeviceReport {
    /// The public key inside the certificate the host offered, in DER.
    client_spki: Option<Vec<u8>>,
    /// Plaintext the host sent inside TLS.
    received: Vec<u8>,
    /// Whether the handshake completed on the device's side.
    handshake_ok: bool,
    /// Whether the device turned the host's certificate down.
    refused_key: bool,
}

/// Whether a device-side failure was the device's own verifier turning
/// the host's certificate down, rather than anything else going wrong.
fn refused_the_key(error: &std::io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidCertificate(_))
    )
}

/// Start a device that demands TLS. It answers whatever the host sends
/// with the same bytes reversed, so a test can tell a real round trip
/// from an accident.
fn spawn_device(policy: KeyPolicy) -> (SocketAddr, JoinHandle<DeviceReport>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let config = device_config(policy);

        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(conn, socket);

        let mut report = DeviceReport {
            client_spki: None,
            received: Vec::new(),
            handshake_ok: false,
            refused_key: false,
        };

        // The handshake runs on the first read.
        let mut buf = [0u8; 256];
        match tls.read(&mut buf) {
            Ok(n) => {
                report.handshake_ok = true;
                report.received.extend_from_slice(&buf[..n]);
                report.client_spki = tls
                    .conn
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| c.as_ref().to_vec());
                let mut echo: Vec<u8> = report.received.clone();
                echo.reverse();
                let _ = tls.write_all(&echo);
                let _ = tls.flush();
            }
            Err(e) => {
                report.refused_key = refused_the_key(&e);
            }
        }
        report
    });

    (addr, handle)
}

fn client_config() -> TlsClientConfig {
    let identity = TlsIdentity::from_key(&host_key(), &mut OsRng).unwrap();
    TlsClientConfig::adb(&identity).unwrap()
}

async fn connected(addr: SocketAddr) -> MaybeTls<rt::AdbTransport> {
    let stream = rt::connect(addr).await;
    let mut transport = MaybeTls::plain(rt::wrap(stream));
    transport.start_tls(&client_config()).await.unwrap();
    transport
}

rt_test! {
async fn a_tls_session_carries_plaintext_both_ways() {
    let (addr, device) = spawn_device(KeyPolicy::Accept);

    let mut transport = connected(addr).await;
    assert!(transport.is_tls(), "the transport reports the session it started");
    assert!(!transport.is_plain());

    transport.write(b"ping over tls").await.unwrap();
    transport.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = transport.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"slt revo gnip", "the device echoed it reversed");

    let report = device.join().unwrap();
    assert!(report.handshake_ok);
    assert_eq!(report.received, b"ping over tls");
}
}

rt_test! {
async fn the_device_is_shown_the_host_key_inside_the_certificate() {
    // This is the whole mechanism: adbd reads the public key out of the
    // client certificate and looks it up among the keys it trusts.
    let (addr, device) = spawn_device(KeyPolicy::Accept);

    let mut transport = connected(addr).await;
    transport.write(b"x").await.unwrap();
    transport.flush().await.unwrap();

    let report = device.join().unwrap();
    let offered = report.client_spki.expect("a client certificate was required");
    let expected = cert::build(&host_key(), &mut OsRng).unwrap();

    // The two certificates differ in their validity dates, so compare
    // the part the device actually looks at.
    assert_eq!(spki_of(&offered), spki_of(&expected));
}
}

/// A device that serves two connections from one configuration, whose
/// session cache would let the second resume the first. Reports how
/// each handshake went and how many certificates it was shown.
fn spawn_device_that_would_resume() -> (SocketAddr, JoinHandle<(Vec<rustls::HandshakeKind>, usize)>)
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let shown = Arc::new(AtomicUsize::new(0));
        let config = device_config_counting(KeyPolicy::Accept, Arc::clone(&shown));
        let mut kinds = Vec::new();
        for _ in 0..2 {
            let (socket, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut tls = StreamOwned::new(conn, socket);
            // Echoing a message makes the host read past the tickets.
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).unwrap();
            tls.write_all(&buf[..n]).unwrap();
            tls.flush().unwrap();
            kinds.push(tls.conn.handshake_kind().unwrap());
            let _ = tls.read(&mut buf);
        }
        (kinds, shown.load(Ordering::Relaxed))
    });

    (addr, handle)
}

rt_test! {
async fn a_second_connection_does_not_resume_the_first() {
    // Every device answers to the one placeholder name, so a ticket from
    // one would be offered to the next, in the clear, and a device that
    // took it up would never see the certificate it knows the host by.
    let (addr, device) = spawn_device_that_would_resume();

    let config = client_config();
    for _ in 0..2 {
        let mut transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
        transport.start_tls(&config).await.unwrap();
        transport.write(b"ping").await.unwrap();
        transport.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    let (kinds, shown) = device.join().unwrap();
    assert_eq!(kinds, [rustls::HandshakeKind::Full, rustls::HandshakeKind::Full]);
    assert_eq!(shown, 2, "the device checked the host's certificate both times");
}
}

rt_test! {
async fn a_rejected_key_surfaces_on_the_first_read_not_the_handshake() {
    // TLS 1.3 tells the client nothing when the server refuses its
    // certificate: the handshake completes locally and the alert
    // arrives with the first read. Anything built on this transport has
    // to expect that.
    let (addr, device) = spawn_device(KeyPolicy::Reject);

    let stream = rt::connect(addr).await;
    let mut transport = MaybeTls::plain(rt::wrap(stream));

    // The certificate leaves in the host's last flight, so the device
    // cannot have judged it yet.
    transport
        .start_tls(&client_config())
        .await
        .expect("the handshake completes on the host's side");
    let mut buf = [0u8; 64];
    let Err(err) = transport.read(&mut buf).await else {
        panic!("a device that refused the key must not hand out a working session");
    };

    assert!(
        matches!(err, TlsError::Tls(rustls::Error::AlertReceived(_))) && err.is_key_rejected(),
        "the refusal must arrive as an alert and be recognised as one, got {err:?}"
    );
    assert!(
        device.join().unwrap().refused_key,
        "the device turned the key down itself"
    );
}
}

rt_test! {
async fn a_split_session_reads_and_writes_at_once() {
    let (addr, device) = spawn_device(KeyPolicy::Accept);

    let transport = connected(addr).await;
    let (mut reader, mut writer) = transport.split().unwrap();

    writer.write(b"split over tls").await.unwrap();
    writer.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"slt revo tilps");

    let report = device.join().unwrap();
    assert_eq!(report.received, b"split over tls");
}
}

/// A device that reads until the host is done and reports whether the
/// host said so with `close_notify`, rather than just hanging up.
fn spawn_device_that_waits_for_the_end() -> (SocketAddr, JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(device_config(KeyPolicy::Accept)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        let mut buf = [0u8; 256];
        loop {
            match tls.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => {}
                // rustls calls a hangup without `close_notify` a truncation.
                Err(_) => return false,
            }
        }
    });

    (addr, handle)
}

rt_test! {
async fn a_split_session_can_still_say_it_is_done() {
    // `split` consumes the session, and `shutdown` with it, so a split
    // connection could only hang up: to the peer, just like one cut short.
    let (addr, device) = spawn_device_that_waits_for_the_end();
    let (reader, mut writer) = connected(addr).await.split().unwrap();

    writer.shutdown().await.unwrap();
    drop((reader, writer));

    assert!(
        device.join().unwrap(),
        "the device saw a bare hangup, not close_notify"
    );
}
}

rt_test! {
async fn a_split_session_that_just_hangs_up_is_told_apart() {
    // The same device, left without `close_notify`, so the test above
    // shows what it claims to.
    let (addr, device) = spawn_device_that_waits_for_the_end();
    let (reader, writer) = connected(addr).await.split().unwrap();

    drop((reader, writer));

    assert!(!device.join().unwrap(), "a bare hangup passed for close_notify");
}
}

/// What a [`spawn_quiet_device`] does next.
enum Step {
    /// Send these bytes.
    Say(&'static [u8]),
    /// Put these bytes on the socket as they are, outside TLS.
    Raw(&'static [u8]),
    /// Send the first bytes, and the second as they are right behind
    /// them, in one write, so the host takes both off the socket at once.
    SayThenRaw(&'static [u8], &'static [u8]),
    /// Read until this much plaintext has arrived, then send these bytes.
    Hear(usize, &'static [u8]),
}

/// A device that finishes the handshake and then reads nothing until
/// told to, so a test can fill the socket towards it first. It hangs up
/// once the sender is dropped.
fn spawn_quiet_device() -> (SocketAddr, mpsc::Sender<Step>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (steps, orders) = mpsc::channel();

    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(device_config(KeyPolicy::Accept)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).unwrap();
        }
        tls.flush().unwrap();

        for step in orders {
            let answer = match step {
                Step::Say(bytes) => bytes,
                Step::Raw(bytes) => {
                    tls.sock.write_all(bytes).unwrap();
                    continue;
                }
                Step::SayThenRaw(said, raw) => {
                    tls.conn.writer().write_all(said).unwrap();
                    let mut wire = Vec::new();
                    while tls.conn.wants_write() {
                        tls.conn.write_tls(&mut wire).unwrap();
                    }
                    wire.extend_from_slice(raw);
                    tls.sock.write_all(&wire).unwrap();
                    continue;
                }
                Step::Hear(total, bytes) => {
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut heard = 0;
                    while heard < total {
                        match tls.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => heard += n,
                        }
                    }
                    bytes
                }
            };
            tls.write_all(answer).unwrap();
            tls.flush().unwrap();
        }
    });

    (addr, steps, handle)
}

rt_test! {
async fn an_idle_read_does_not_wait_behind_a_writer_stuck_on_the_socket() {
    // A device that reads nothing leaves the writer blocked inside its
    // drain with the write lock held. A read that queued for that lock
    // would stop reading the socket, and a peer that will not read until
    // it has been read from would then leave both sides stuck.
    //
    // The writer is held in place rather than stuck on a real full
    // socket: one that stalled can still take a few more bytes once the
    // device's reply reopens the window, so there is no telling from the
    // outside whether it was stuck through the read.
    let (addr, steps, device) = spawn_quiet_device();
    let (transport, faults) = breakable_session(addr).await;
    let (mut reader, mut writer) = transport.split().unwrap();

    faults.held.store(true, Ordering::Relaxed);
    let returned = Arc::new(AtomicBool::new(false));
    let held = rt::spawn({
        let returned = Arc::clone(&returned);
        async move {
            // The write only queues; the flush is what meets the socket.
            let _ = writer.write(b"held").await;
            let _ = writer.flush().await;
            returned.store(true, Ordering::Relaxed);
        }
    });
    faults.until_holding().await;

    steps.send(Step::Say(b"hello")).unwrap();
    let mut buf = [0u8; 16];
    let n = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read queued behind the stuck writer")
        .unwrap();

    assert_eq!(&buf[..n], b"hello");
    assert!(
        !returned.load(Ordering::Relaxed),
        "the writer must still be stuck, or the read proved nothing"
    );
    faults.held.store(false, Ordering::Relaxed);
    rt::join(held).await;
    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn a_write_dropped_on_a_full_socket_leaves_the_queue_for_the_next_flush() {
    // A write dropped while the queue ahead of it went out has committed
    // nothing of its own, and the queue is still there: the next flush
    // finishes sending it, and the device gets every byte the writes
    // reported.
    let (addr, steps, device) = spawn_quiet_device();
    let (mut reader, mut writer) = connected(addr).await.split().unwrap();

    let chunk = [0xa5; 4096];
    let mut reported = 0;
    while let Some(n) = rt::timeout_ms(300, writer.write(&chunk)).await {
        reported += n.unwrap();
    }

    steps.send(Step::Hear(reported, b"all of it")).unwrap();
    rt::timeout_ms(5000, writer.flush())
        .await
        .expect("the flush never finished sending the queue")
        .unwrap();
    let mut buf = [0u8; 16];
    let n = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the device never heard all of it")
        .unwrap();

    assert_eq!(&buf[..n], b"all of it");
    drop(steps);
    device.join().unwrap();
}
}

/// A device that finishes the handshake and reads nothing until told
/// how much to expect; then it reads that much and hands it back.
fn spawn_device_that_listens_late() -> (SocketAddr, mpsc::Sender<usize>, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (expect, told) = mpsc::channel::<usize>();

    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(device_config(KeyPolicy::Accept)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).unwrap();
        }
        tls.flush().unwrap();

        let total = told.recv().unwrap();
        // A host that sent too little would leave this waiting for good.
        tls.sock
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut heard = Vec::with_capacity(total);
        let mut buf = vec![0u8; 64 * 1024];
        while heard.len() < total {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => heard.extend_from_slice(&buf[..n]),
            }
        }
        heard
    });

    (addr, expect, handle)
}

/// Write 4 MiB of numbered chunks towards a device that is not reading
/// until one write is held up and dropped, then tell the device to read
/// and send the rest, starting again from the dropped chunk as a caller
/// would. Returns what the device should have heard.
async fn write_through_a_dropped_write<W: Write>(w: &mut W, expect: &mpsc::Sender<usize>) -> Vec<u8>
where
    W::Error: core::fmt::Debug,
{
    let chunks: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| {
            let mut chunk = vec![0u8; 4096];
            chunk[..4].copy_from_slice(&i.to_le_bytes());
            chunk
        })
        .collect();

    let mut next = 0;
    while let Some(n) = rt::timeout_ms(200, w.write(&chunks[next])).await {
        assert_eq!(n.unwrap(), chunks[next].len());
        next += 1;
        assert!(
            next < chunks.len(),
            "no write was held up, so nothing is tested"
        );
    }

    expect.send(chunks.len() * 4096).unwrap();
    for chunk in &chunks[next..] {
        w.write_all(chunk).await.unwrap();
    }
    w.flush().await.unwrap();
    chunks.concat()
}

rt_test! {
async fn a_write_dropped_on_a_full_socket_is_not_sent_twice() {
    // A caller whose write was dropped sends the same bytes again, as it
    // would over a plain socket. A write that had sealed them before it
    // waited on the socket sent them twice.
    let (addr, expect, device) = spawn_device_that_listens_late();
    let mut transport = connected(addr).await;

    let sent = write_through_a_dropped_write(&mut transport, &expect).await;

    assert!(
        device.join().unwrap() == sent,
        "the device heard some of it twice, or not at all"
    );
}
}

rt_test! {
async fn a_split_write_dropped_on_a_full_socket_is_not_sent_twice() {
    let (addr, expect, device) = spawn_device_that_listens_late();
    let (_reader, mut writer) = connected(addr).await.split().unwrap();

    let sent = write_through_a_dropped_write(&mut writer, &expect).await;

    assert!(
        device.join().unwrap() == sent,
        "the device heard some of it twice, or not at all"
    );
}
}

/// An application-data record of 32 zero bytes, sealed under no key.
const BROKEN_RECORD: [u8; 37] = {
    let mut record = [0u8; 37];
    record[0] = 0x17;
    record[1] = 0x03;
    record[2] = 0x03;
    record[4] = 32;
    record
};

rt_test! {
async fn a_broken_record_fails_the_read_rather_than_ending_it() {
    // A record that will not decrypt has to reach the caller as the TLS
    // failure it is. Read as a clean end of stream, it would pass for a
    // device that hung up, and a connect takes that for a refused key.
    let (addr, steps, device) = spawn_quiet_device();
    let mut transport = connected(addr).await;

    steps.send(Step::Raw(&BROKEN_RECORD)).unwrap();
    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung");

    let Err(err) = outcome else {
        panic!("a broken record read as {outcome:?}");
    };
    assert!(matches!(err, TlsError::Tls(_)), "got {err:?}");
    assert!(!err.is_key_rejected());
    drop(steps);
    device.join().unwrap();
}
}

/// A device that answers the ClientHello with a ServerHello claiming
/// 32 KiB, cut into one-byte records, and then stays on the line until
/// the host hangs up.
fn spawn_device_that_floods_the_handshake() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut head = [0u8; 5];
        socket.read_exact(&mut head).unwrap();
        let mut hello = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
        socket.read_exact(&mut hello).unwrap();

        // Every record costs six bytes for the one it carries, so the
        // buffer rustls joins the message in fills long before the
        // message is whole.
        let mut message = vec![0u8; 4 + 0x8000];
        message[..4].copy_from_slice(&[0x02, 0x00, 0x80, 0x00]);
        let records: Vec<u8> = message
            .iter()
            .flat_map(|&b| [0x16, 0x03, 0x03, 0x00, 0x01, b])
            .collect();
        // A host that gives up closes the socket, which ends this early.
        let _ = socket.write_all(&records);

        // A host that went on reading would wait here for good.
        let mut sink = [0u8; 4096];
        while matches!(socket.read(&mut sink), Ok(n) if n > 0) {}
    });

    (addr, handle)
}

rt_test! {
async fn a_handshake_message_too_big_to_buffer_fails_the_handshake() {
    // rustls refuses records once it holds 64 KiB of one handshake
    // message, and says so with an error. Taken for backpressure, that
    // left the handshake reading for as long as the peer kept the
    // socket open, and keeping everything it sent.
    let (addr, device) = spawn_device_that_floods_the_handshake();
    let mut transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));

    let outcome = rt::timeout_ms(5000, transport.start_tls(&client_config()))
        .await
        .expect("the handshake hung on a message rustls would not buffer");

    let Err(err) = outcome else {
        panic!("a handshake with no ServerHello completed");
    };
    assert!(matches!(err, TlsError::Tls(_)), "got {err:?}");
    assert!(!err.is_key_rejected());
    device.join().unwrap();
}
}

/// Hands out session tickets of 40,000 bytes. Nothing is wrong with one
/// that size, but sent in the smallest records rustls allows it
/// overflows the buffer the host joins a handshake message in.
#[derive(Debug)]
struct OutsizedTickets;

impl rustls::server::ProducesTickets for OutsizedTickets {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        60
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        Some(vec![0; 40_000])
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// A device that finishes the handshake, sends one outsized ticket in
/// 32-byte records, and stays on the line until the host hangs up.
fn spawn_device_with_an_outsized_ticket() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let mut config = (*device_config(KeyPolicy::Accept)).clone();
        config.ticketer = Arc::new(OutsizedTickets);
        config.send_tls13_tickets = 1;
        config.max_fragment_size = Some(32);

        let (socket, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).unwrap();
        }
        // The ticket goes out once the handshake is over. A host that
        // gives up closes the socket, which may cut it short.
        let _ = tls.flush();

        let mut sink = [0u8; 4096];
        while matches!(tls.sock.read(&mut sink), Ok(n) if n > 0) {}
    });

    (addr, handle)
}

rt_test! {
async fn a_ticket_too_big_to_buffer_fails_the_read() {
    // The same refusal after the handshake, where the read loop has to
    // report it rather than go back to the socket.
    let (addr, device) = spawn_device_with_an_outsized_ticket();
    let mut transport = connected(addr).await;

    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung on a message rustls would not buffer");

    assert!(matches!(outcome, Err(TlsError::Tls(_))), "got {outcome:?}");
    drop(transport);
    device.join().unwrap();
}
}

rt_test! {
async fn a_ticket_too_big_to_buffer_fails_a_split_read_too() {
    let (addr, device) = spawn_device_with_an_outsized_ticket();
    let (mut reader, writer) = connected(addr).await.split().unwrap();

    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the split read hung on a message rustls would not buffer");

    assert!(matches!(outcome, Err(TlsError::Tls(_))), "got {outcome:?}");
    drop((reader, writer));
    device.join().unwrap();
}
}

#[test]
fn only_an_alert_about_the_certificate_counts_as_a_refused_key() {
    // adbd turns a key away with `certificate_unknown`. A generic alert
    // is a handshake that failed for some other reason, and reporting
    // it as a refused key would have the user pair a key that is fine.
    use rustls::AlertDescription as A;
    let refused = |alert: A| {
        TlsError::<core::convert::Infallible>::Tls(rustls::Error::AlertReceived(alert))
            .is_key_rejected()
    };

    for alert in [A::CertificateUnknown, A::BadCertificate, A::AccessDenied] {
        assert!(refused(alert), "{alert:?} is a refusal");
    }
    for alert in [
        A::HandshakeFailure,
        A::DecryptError,
        A::ProtocolVersion,
        A::InternalError,
        // No certificate arrived at all, which pairing cannot cure.
        A::CertificateRequired,
    ] {
        assert!(!refused(alert), "{alert:?} says nothing about the key");
    }
}

/// What a test can do to the writes of a [`BreakableWrites`] socket.
#[derive(Default)]
struct WriteFaults {
    /// Fail every write and flush, as once the device has reset the
    /// connection.
    broken: AtomicBool,
    /// Hold every write in place, as a socket the device reads nothing
    /// from does, until this goes down again. Flushes pass: a write is
    /// what has bytes to be stuck on.
    held: AtomicBool,
    /// Whether a write has been held.
    holding: AtomicBool,
}

impl WriteFaults {
    /// What a write meets on its way to the socket.
    async fn write(&self) -> Result<(), std::io::Error> {
        while self.held.load(Ordering::Relaxed) {
            self.holding.store(true, Ordering::Relaxed);
            rt::sleep_ms(10).await;
        }
        self.flush()
    }

    /// What a flush meets on its way to the socket.
    fn flush(&self) -> Result<(), std::io::Error> {
        if self.broken.load(Ordering::Relaxed) {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }

    /// Wait until a write is being held.
    async fn until_holding(&self) {
        while !self.holding.load(Ordering::Relaxed) {
            rt::sleep_ms(10).await;
        }
    }
}

/// A socket whose writes can be made to fail, as they do once the
/// device has reset the connection, or to hang, as they do when the
/// device reads nothing, while its reads carry on.
struct BreakableWrites {
    inner: rt::AdbTransport,
    faults: Arc<WriteFaults>,
}

/// The write half of a [`BreakableWrites`].
struct BreakableHalf {
    inner: <rt::AdbTransport as Splittable>::WriteHalf,
    faults: Arc<WriteFaults>,
}

impl embedded_io_async::ErrorType for BreakableWrites {
    type Error = std::io::Error;
}

impl embedded_io_async::ErrorType for BreakableHalf {
    type Error = std::io::Error;
}

impl Read for BreakableWrites {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.read(buf).await
    }
}

impl Write for BreakableWrites {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.faults.write().await?;
        self.inner.write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.faults.flush()?;
        self.inner.flush().await
    }
}

impl Write for BreakableHalf {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.faults.write().await?;
        self.inner.write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.faults.flush()?;
        self.inner.flush().await
    }
}

impl Splittable for BreakableWrites {
    type ReadHalf = <rt::AdbTransport as Splittable>::ReadHalf;
    type WriteHalf = BreakableHalf;

    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        let (read, write) = self.inner.split()?;
        let write = BreakableHalf {
            inner: write,
            faults: self.faults,
        };
        Ok((read, write))
    }
}

/// A TLS session to a quiet device over a socket whose writes fail or
/// hang as the returned faults say.
async fn breakable_session(addr: SocketAddr) -> (MaybeTls<BreakableWrites>, Arc<WriteFaults>) {
    let faults = Arc::new(WriteFaults::default());
    let socket = BreakableWrites {
        inner: rt::wrap(rt::connect(addr).await),
        faults: Arc::clone(&faults),
    };
    let mut transport = MaybeTls::plain(socket);
    transport.start_tls(&client_config()).await.unwrap();
    (transport, faults)
}

rt_test! {
async fn a_split_read_still_names_a_broken_record_when_its_alert_cannot_go_out() {
    // The alert for the record is owed and the socket will no longer
    // take it. That is for the writer to report; what the reader has
    // to say is that the record would not decrypt.
    let (addr, steps, device) = spawn_quiet_device();
    let (transport, faults) = breakable_session(addr).await;
    let (mut reader, _writer) = transport.split().unwrap();

    faults.broken.store(true, Ordering::Relaxed);
    steps.send(Step::Raw(&BROKEN_RECORD)).unwrap();
    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read hung");

    assert!(
        matches!(outcome, Err(TlsError::Tls(_))),
        "got {outcome:?}"
    );
    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn a_split_read_still_delivers_what_arrived_when_the_writer_is_stuck() {
    // A flush that failed leaves its records queued. That is the
    // writer's to report, and must not cost the reader what the device
    // has already sent.
    let (addr, steps, device) = spawn_quiet_device();
    let (transport, faults) = breakable_session(addr).await;
    let (mut reader, mut writer) = transport.split().unwrap();

    faults.broken.store(true, Ordering::Relaxed);
    writer.write(b"never sent").await.unwrap();
    assert!(writer.flush().await.is_err());
    steps.send(Step::Say(b"the tail")).unwrap();
    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read hung");

    assert_eq!(outcome.map(|n| &buf[..n]).ok(), Some(&b"the tail"[..]));
    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn an_unsplit_read_still_delivers_what_arrived_when_the_writer_is_stuck() {
    // The same, before any split: the records of the failed flush wait
    // in the session, and the read carries on without them.
    let (addr, steps, device) = spawn_quiet_device();
    let (mut transport, faults) = breakable_session(addr).await;

    faults.broken.store(true, Ordering::Relaxed);
    transport.write(b"never sent").await.unwrap();
    assert!(transport.flush().await.is_err());
    steps.send(Step::Say(b"the tail")).unwrap();
    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung");

    assert_eq!(outcome.map(|n| &buf[..n]).ok(), Some(&b"the tail"[..]));
    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn a_split_read_names_a_broken_record_while_the_writer_is_held_up() {
    // The alert for a broken record is the writer's to carry. A reader
    // that sent it itself queued behind a writer held up on the socket,
    // and the failure did not surface until that writer let go.
    let (addr, steps, device) = spawn_quiet_device();
    let (transport, faults) = breakable_session(addr).await;
    let (mut reader, mut writer) = transport.split().unwrap();

    faults.held.store(true, Ordering::Relaxed);
    let held = rt::spawn(async move {
        let _ = writer.write(b"held").await;
        let _ = writer.flush().await;
    });
    faults.until_holding().await;

    steps.send(Step::Raw(&BROKEN_RECORD)).unwrap();
    let mut buf = [0u8; 16];
    let outcome = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read waited for the writer");
    assert!(matches!(outcome, Err(TlsError::Tls(_))), "got {outcome:?}");

    faults.held.store(false, Ordering::Relaxed);
    rt::join(held).await;
    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn a_broken_record_is_not_lost_to_a_dropped_read() {
    // `select_channel` drops a read when something else comes first, so
    // a failure has to outlive the read that met it. Sending the alert
    // from the read kept the failure in a local across the wait for the
    // socket, and a read dropped there took it along: the next one found
    // nothing to decrypt and took the hangup for a clean end of stream.
    let (addr, steps, device) = spawn_quiet_device();
    let (mut transport, faults) = breakable_session(addr).await;

    faults.held.store(true, Ordering::Relaxed);
    steps.send(Step::Raw(&BROKEN_RECORD)).unwrap();
    let mut buf = [0u8; 16];
    if let Some(outcome) = rt::timeout_ms(1000, transport.read(&mut buf)).await {
        assert!(matches!(outcome, Err(TlsError::Tls(_))), "got {outcome:?}");
    }

    // The device hangs up, as it would after the alert.
    faults.held.store(false, Ordering::Relaxed);
    drop(steps);
    device.join().unwrap();

    let outcome = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung");
    assert!(
        matches!(outcome, Err(TlsError::Tls(_))),
        "the failure was lost: {outcome:?}"
    );
}
}

rt_test! {
async fn a_session_that_met_a_broken_record_stays_failed() {
    // Only the read that met the record reported it. The next found
    // nothing to decrypt and went back to the socket, and a write went
    // out after the fatal alert as if nothing had happened.
    let (addr, steps, device) = spawn_quiet_device();
    let mut transport = connected(addr).await;

    steps.send(Step::Raw(&BROKEN_RECORD)).unwrap();
    let mut buf = [0u8; 16];
    let first = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung");
    assert!(matches!(first, Err(TlsError::Tls(_))), "got {first:?}");

    let again = rt::timeout_ms(1000, transport.read(&mut buf))
        .await
        .expect("a read after the failure went back to the socket");
    assert!(matches!(again, Err(TlsError::Tls(_))), "got {again:?}");
    let wrote = transport.write(b"after").await;
    assert!(matches!(wrote, Err(TlsError::Tls(_))), "got {wrote:?}");

    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn a_split_session_that_met_a_broken_record_stays_failed() {
    let (addr, steps, device) = spawn_quiet_device();
    let (mut reader, mut writer) = connected(addr).await.split().unwrap();

    steps.send(Step::Raw(&BROKEN_RECORD)).unwrap();
    let mut buf = [0u8; 16];
    let first = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read hung");
    assert!(matches!(first, Err(TlsError::Tls(_))), "got {first:?}");

    let again = rt::timeout_ms(1000, reader.read(&mut buf))
        .await
        .expect("a read after the failure went back to the socket");
    assert!(matches!(again, Err(TlsError::Tls(_))), "got {again:?}");
    let wrote = writer.write(b"after").await;
    assert!(matches!(wrote, Err(TlsError::Tls(_))), "got {wrote:?}");

    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn what_decrypted_before_a_broken_record_is_read_before_the_failure() {
    // A record that arrived whole ahead of the broken one is the
    // device's own, and rustls has already decrypted it. The failure
    // comes after it, not in its place.
    let (addr, steps, device) = spawn_quiet_device();
    let mut transport = connected(addr).await;

    steps
        .send(Step::SayThenRaw(b"the tail", &BROKEN_RECORD))
        .unwrap();
    let mut buf = [0u8; 16];
    let first = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung");
    assert_eq!(first.map(|n| &buf[..n]).ok(), Some(&b"the tail"[..]));

    let second = rt::timeout_ms(5000, transport.read(&mut buf))
        .await
        .expect("the read hung");
    assert!(matches!(second, Err(TlsError::Tls(_))), "got {second:?}");

    drop(steps);
    device.join().unwrap();
}
}

rt_test! {
async fn what_decrypted_before_a_broken_record_is_read_before_the_failure_when_split() {
    let (addr, steps, device) = spawn_quiet_device();
    let (mut reader, _writer) = connected(addr).await.split().unwrap();

    steps
        .send(Step::SayThenRaw(b"the tail", &BROKEN_RECORD))
        .unwrap();
    let mut buf = [0u8; 16];
    let first = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read hung");
    assert_eq!(first.map(|n| &buf[..n]).ok(), Some(&b"the tail"[..]));

    let second = rt::timeout_ms(5000, reader.read(&mut buf))
        .await
        .expect("the read hung");
    assert!(matches!(second, Err(TlsError::Tls(_))), "got {second:?}");

    drop(steps);
    device.join().unwrap();
}
}

/// A transport whose every write takes nothing.
struct TakesNothing;

impl embedded_io_async::ErrorType for TakesNothing {
    type Error = core::convert::Infallible;
}

impl Read for TakesNothing {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

impl Write for TakesNothing {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

rt_test! {
async fn a_write_that_goes_nowhere_is_not_taken_for_a_refused_key() {
    // A transport that takes no bytes has refused nothing, and calling
    // it a refusal would send the user off to pair a key that was never
    // the problem.
    let mut transport = MaybeTls::plain(TakesNothing);

    let err = transport.start_tls(&client_config()).await.unwrap_err();

    assert!(matches!(err, TlsError::WriteZero), "got {err:?}");
    assert!(!err.is_key_rejected());
}
}

rt_test! {
async fn a_plain_transport_still_splits_and_passes_bytes_through() {
    // Without an upgrade the wrapper must be invisible, because the
    // handshake runs through it before anyone knows whether the device
    // wants TLS at all.
    let (listener, addr) = rt::bind_loopback().await;
    let device = rt::spawn(async move {
        let mut socket = rt::accept_one(&listener).await;
        let mut buf = [0u8; 5];
        rt::read_exact(&mut socket, &mut buf).await;
        rt::write_all(&mut socket, b"pong!").await;
        buf
    });

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    assert!(transport.is_plain());
    let (mut reader, mut writer) = transport.split().unwrap();

    writer.write(b"ping!").await.unwrap();
    let mut buf = [0u8; 5];
    reader.read(&mut buf).await.unwrap();

    assert_eq!(&buf, b"pong!");
    assert_eq!(&rt::join(device).await, b"ping!");
}
}

/// The `subjectPublicKeyInfo` of a DER certificate, found by structure
/// rather than parsed: it is the only 290-byte SEQUENCE in an RSA-2048
/// certificate, and this test only needs to compare two of them.
fn spki_of(der: &[u8]) -> Vec<u8> {
    let needle = [0x30u8, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09];
    let at = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("an RSA-2048 SubjectPublicKeyInfo");
    der[at..at + 294].to_vec()
}

// ---------------------------------------------------------------------
// The whole handshake: STLS, then ADB inside the session
// ---------------------------------------------------------------------

use libadb::error::{AuthError, ProtocolError};
use libadb::protocol::command::{
    Command, AUTH_SIGNATURE, AUTH_TOKEN, CMD_AUTH, CMD_CNXN, CMD_OKAY, CMD_STLS,
};
use libadb::protocol::constant::{ADB_VERSION, STLS_VERSION};
use libadb::{Connection, Error};

const DEVICE_BANNER: &[u8] = b"device::features=shell_v2,cmd";

fn header(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(24 + payload.len());
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&arg0.to_le_bytes());
    h.extend_from_slice(&arg1.to_le_bytes());
    h.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let sum: u32 = payload.iter().map(|&b| b as u32).sum();
    h.extend_from_slice(&sum.to_le_bytes());
    h.extend_from_slice(&(command ^ 0xFFFF_FFFF).to_le_bytes());
    h.extend_from_slice(payload);
    h
}

fn read_packet(r: &mut impl std::io::Read) -> (u32, u32, u32, Vec<u8>) {
    let mut h = [0u8; 24];
    r.read_exact(&mut h).unwrap();
    let word = |i: usize| u32::from_le_bytes(h[i * 4..i * 4 + 4].try_into().unwrap());
    let len = word(3) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).unwrap();
    }
    (word(0), word(1), word(2), payload)
}

/// What the device saw the host do.
struct HandshakeReport {
    /// arg0 and arg1 of the host's own STLS.
    host_stls: (u32, u32),
    /// Whether the host's STLS carried a payload. AOSP's carries none.
    host_stls_payload: usize,
    /// Whether the host repeated its CNXN inside the session. It must
    /// not: the device speaks first there.
    repeated_cnxn: bool,
    /// Whether the device turned the host's certificate down.
    refused_key: bool,
}

/// A device that demands TLS and then talks ADB inside it.
fn spawn_adb_device(policy: KeyPolicy) -> (SocketAddr, JoinHandle<HandshakeReport>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let config = device_config(policy);

        let (mut socket, _) = listener.accept().unwrap();

        // In the clear: the host's CNXN, then our demand for TLS.
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_CNXN, "the host opens with CNXN");
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();

        let (command, arg0, arg1, payload) = read_packet(&mut socket);
        assert_eq!(command, CMD_STLS, "the host answers STLS with STLS");
        let mut report = HandshakeReport {
            host_stls: (arg0, arg1),
            host_stls_payload: payload.len(),
            repeated_cnxn: false,
            refused_key: false,
        };

        // From here on, TLS.
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        // The device speaks first inside the session.
        if let Err(e) = tls.write_all(&header(CMD_CNXN, ADB_VERSION, 256 * 1024, DEVICE_BANNER)) {
            report.refused_key = refused_the_key(&e);
            return report;
        }
        let _ = tls.flush();

        // Nothing should arrive until the host opens a channel.
        tls.sock
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut probe = [0u8; 24];
        if let Ok(24) = tls.read(&mut probe) {
            report.repeated_cnxn = u32::from_le_bytes(probe[0..4].try_into().unwrap()) == CMD_CNXN;
        }
        report
    });

    (addr, handle)
}

rt_test! {
async fn a_device_that_demands_tls_ends_up_connected() {
    let (addr, device) = spawn_adb_device(KeyPolicy::Accept);

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let conn = Connection::<_>::connect_tls(
        transport,
        test_auth(),
        &[],
        &client_config(),
    )
    .await
    .expect("a device that offers TLS and trusts the key connects");

    assert!(conn.transport().is_tls(), "the session is running");
    assert_eq!(conn.device_banner(), Some(DEVICE_BANNER));

    let report = device.join().unwrap();
    assert_eq!(report.host_stls, (STLS_VERSION, 0), "the host mirrors the offer");
    assert_eq!(report.host_stls_payload, 0, "STLS carries no payload");
    assert!(!report.repeated_cnxn, "the host waits rather than repeating CNXN");
}
}

rt_test! {
async fn a_key_the_device_will_not_have_is_named_as_such() {
    let (addr, device) = spawn_adb_device(KeyPolicy::Reject);

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let Err(err) = Connection::<_>::connect_tls(
        transport,
        test_auth(),
        &[],
        &client_config(),
    )
    .await
    else {
        panic!("a device that refuses the key must not hand back a connection");
    };

    assert!(
        matches!(err, Error::Auth(libadb::error::AuthError::TlsKeyNotTrusted)),
        "expected TlsKeyNotTrusted, got {err:?}"
    );
    // And it was the device's verdict on the key, not some other way of
    // coming to an end, which the connect path would read the same way.
    assert!(
        device.join().unwrap().refused_key,
        "the device turned the key down itself"
    );
}
}

rt_test! {
async fn a_device_that_never_asks_for_tls_is_served_in_the_clear() {
    // One entry point covers both kinds of device, so a caller does not
    // have to know which port it dialled.
    let (handle, addr) = fake_device::FakeDevice::new().bind().await;
    let device = rt::spawn(async move { handle.accept().await });

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let conn = Connection::<_>::connect_tls(
        transport,
        test_auth(),
        &[],
        &client_config(),
    )
    .await
    .expect("a plain device still connects");

    assert!(conn.transport().is_plain(), "nothing was upgraded");
    drop(device);
}
}

rt_test! {
async fn a_usb_transport_connects_through_connect_tls_all_the_same() {
    // adbd never offers STLS over USB, and the USB half cannot start
    // TLS at all, so this works only because TLS is started on the
    // device's say-so, never up front. A socket stands in for the USB
    // half: the variant is what matters, not the wire.
    let (handle, addr) = fake_device::FakeDevice::new().bind().await;
    let device = rt::spawn(async move { handle.accept().await });

    let usb = rt::wrap(rt::connect(addr).await);
    let transport = Transport::<MaybeTls<rt::AdbTransport>, _>::Usb(usb);
    let conn = Connection::<_>::connect_tls(transport, test_auth(), &[], &client_config())
        .await
        .expect("USB connects through connect_tls as it does through connect");

    assert!(matches!(conn.transport(), Transport::Usb(_)));
    drop(device);
}
}

/// A device that asks for TLS, reads the ClientHello, answers it with
/// `reply` and hangs up, long before the host's certificate could have
/// reached it.
fn spawn_device_that_stops_at_the_hello(reply: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_CNXN, "the host opens with CNXN");
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_STLS, "the host answers STLS with STLS");

        // All of the ClientHello record, so the close is a clean FIN
        // rather than a reset over unread bytes.
        let mut head = [0u8; 5];
        socket.read_exact(&mut head).unwrap();
        let mut hello = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
        socket.read_exact(&mut hello).unwrap();
        socket.write_all(reply).unwrap();
    });

    (addr, handle)
}

rt_test! {
async fn a_device_that_hangs_up_mid_handshake_is_not_said_to_refuse_the_key() {
    // Under TLS 1.3 the host's certificate travels in its last flight,
    // after the handshake is over on its side. A device gone before
    // then never saw the key, and pairing again would cure nothing.
    let (addr, device) = spawn_device_that_stops_at_the_hello(&[]);

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let Err(err) =
        Connection::<_>::connect_tls(transport, test_auth(), &[], &client_config()).await
    else {
        panic!("a device that hung up must not hand out a connection");
    };

    assert!(
        matches!(err, Error::Io(TlsError::HandshakeClosed)),
        "expected the handshake cut short, got {err:?}"
    );
    device.join().unwrap();
}
}

/// Connect over TLS to a device that must not let the host in, and say
/// why it did not.
async fn failed_connect(
    addr: SocketAddr,
    tls: &TlsClientConfig,
) -> Error<TlsError<std::io::Error>> {
    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let connect = Connection::<_>::connect_tls(transport, test_auth(), &[], tls);
    let outcome = rt::timeout_ms(5000, connect)
        .await
        .expect("the connect hung");
    match outcome {
        Ok(_) => panic!("the device must not have handed out a connection"),
        Err(err) => err,
    }
}

/// A fatal `access_denied` alert, in the clear.
const ACCESS_DENIED: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31];

rt_test! {
async fn an_alert_before_the_host_shows_its_key_is_not_said_to_refuse_it() {
    // An alert in answer to the ClientHello comes before the host's
    // certificate has gone out, whatever the alert says.
    let (addr, device) = spawn_device_that_stops_at_the_hello(&ACCESS_DENIED);

    let err = failed_connect(addr, &client_config()).await;

    assert!(
        matches!(
            err,
            Error::Io(TlsError::Tls(rustls::Error::AlertReceived(
                rustls::AlertDescription::AccessDenied
            )))
        ),
        "expected the alert itself, got {err:?}"
    );
    device.join().unwrap();
}
}

/// A device that asks for TLS with a stray OKAY in the same segment, as
/// a stale packet would sit behind it. Reports whether the host went on
/// to answer the STLS all the same.
fn spawn_device_with_a_packet_behind_its_stls() -> (SocketAddr, JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_CNXN, "the host opens with CNXN");
        let mut segment = header(CMD_STLS, STLS_VERSION, 0, &[]);
        segment.extend_from_slice(&header(CMD_OKAY, 1, 2, &[]));
        socket.write_all(&segment).unwrap();

        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest);
        !rest.is_empty()
    });

    (addr, handle)
}

rt_test! {
async fn a_packet_behind_the_stls_is_named_rather_than_fed_to_tls() {
    // A TLS 1.3 server speaks only after the ClientHello, so what came
    // in the same segment as STLS is plaintext. Handed to rustls as the
    // start of the session, it failed as a corrupt record, which said
    // nothing about what had happened.
    let (addr, device) = spawn_device_with_a_packet_behind_its_stls();

    let err = failed_connect(addr, &client_config()).await;

    assert!(
        matches!(err, Error::Protocol(ProtocolError::DataAfterStls)),
        "got {err:?}"
    );
    assert!(
        !device.join().unwrap(),
        "the host answered STLS it could not carry through"
    );
}
}

/// How a device that took the key leaves before its CNXN is whole.
#[derive(Clone, Copy, Debug)]
enum Departure {
    /// A bare FIN, as when adbd restarts or wireless debugging goes off.
    Fin,
    /// A `close_notify`, then the FIN.
    CloseNotify,
    /// The CNXN header alone, then the FIN.
    HalfCnxn,
}

/// A device that demands TLS, takes the host's key, and leaves as
/// `departure` says instead of sending its CNXN.
fn spawn_device_that_leaves_after_the_handshake(
    departure: Departure,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_CNXN, "the host opens with CNXN");
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_STLS, "the host answers STLS with STLS");

        let conn = ServerConnection::new(device_config(KeyPolicy::Accept)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).unwrap();
        }
        match departure {
            Departure::Fin => {}
            Departure::CloseNotify => {
                tls.conn.send_close_notify();
                tls.flush().unwrap();
            }
            Departure::HalfCnxn => {
                let cnxn = header(CMD_CNXN, ADB_VERSION, 256 * 1024, DEVICE_BANNER);
                tls.write_all(&cnxn[..24]).unwrap();
                tls.flush().unwrap();
            }
        }
    });

    (addr, handle)
}

rt_test! {
async fn a_device_that_leaves_after_the_handshake_is_not_said_to_refuse_the_key() {
    // A device that took the key and then went away, as it does when
    // adbd restarts or wireless debugging goes off, looks just like one
    // that refused the key by closing. Calling it a refusal sent the
    // user off to pair again, spending one of the device's attempts.
    for departure in [Departure::Fin, Departure::CloseNotify] {
        let (addr, device) = spawn_device_that_leaves_after_the_handshake(departure);

        let err = failed_connect(addr, &client_config()).await;

        assert!(
            matches!(err, Error::Auth(AuthError::TlsClosedBeforeConnect)),
            "{departure:?}: got {err:?}"
        );
        device.join().unwrap();
    }
}
}

rt_test! {
async fn a_device_that_leaves_part_way_through_its_cnxn_took_the_key() {
    // Part of a CNXN means the device let the host in and then went
    // away, which is nothing a key can be blamed for.
    let (addr, device) = spawn_device_that_leaves_after_the_handshake(Departure::HalfCnxn);

    let err = failed_connect(addr, &client_config()).await;

    assert!(matches!(err, Error::UnexpectedEof), "got {err:?}");
    device.join().unwrap();
}
}

/// Takes any device certificate, as the host's own profile does.
#[derive(Debug)]
struct TrustAnyDevice {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for TrustAnyDevice {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

rt_test! {
async fn a_profile_without_a_client_certificate_is_not_said_to_have_a_refused_key() {
    // The device asked for a certificate, got none, and said so with
    // `certificate_required`. That is the host's configuration, which
    // pairing cannot cure.
    let (addr, device) = spawn_adb_device(KeyPolicy::Accept);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnyDevice { provider }))
        .with_no_client_auth();
    let tls = TlsClientConfig::from_rustls(Arc::new(config), ServerName::try_from("adb").unwrap());

    let err = failed_connect(addr, &tls).await;

    assert!(
        matches!(
            err,
            Error::Io(TlsError::Tls(rustls::Error::AlertReceived(
                rustls::AlertDescription::CertificateRequired
            )))
        ),
        "expected the alert itself, got {err:?}"
    );
    assert!(!device.join().unwrap().refused_key);
}
}

/// What a device that asks for AUTH inside TLS does with the signature.
#[derive(Clone, Copy, Debug)]
enum AfterSignature {
    /// Close the session, as over a key it will not have.
    Close,
    /// Answer with STLS, which has no place inside TLS.
    Stls,
}

/// A device that demands TLS and then, inside it, asks the host to sign
/// a token instead of sending its CNXN. No AOSP device does; a device
/// of another make might.
fn spawn_device_that_authenticates_inside_tls(
    after: AfterSignature,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_CNXN, "the host opens with CNXN");
        socket
            .write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
            .unwrap();
        let (command, _, _, _) = read_packet(&mut socket);
        assert_eq!(command, CMD_STLS, "the host answers STLS with STLS");

        let conn = ServerConnection::new(device_config(KeyPolicy::Accept)).unwrap();
        let mut tls = StreamOwned::new(conn, socket);
        tls.write_all(&header(CMD_AUTH, AUTH_TOKEN, 0, &[0x42; 20]))
            .unwrap();
        tls.flush().unwrap();
        let (command, arg0, _, _) = read_packet(&mut tls);
        assert_eq!(
            (command, arg0),
            (CMD_AUTH, AUTH_SIGNATURE),
            "the host signs the token"
        );
        match after {
            AfterSignature::Close => {}
            AfterSignature::Stls => {
                tls.write_all(&header(CMD_STLS, STLS_VERSION, 0, &[]))
                    .unwrap();
                tls.flush().unwrap();
            }
        }
    });

    (addr, handle)
}

rt_test! {
async fn a_close_after_the_signature_inside_tls_is_judged_as_one_before_it() {
    // The same close one packet earlier is a device that may have
    // refused the key; after the signature it is no different.
    let (addr, device) = spawn_device_that_authenticates_inside_tls(AfterSignature::Close);

    let err = failed_connect(addr, &client_config()).await;

    assert!(
        matches!(err, Error::Auth(AuthError::TlsClosedBeforeConnect)),
        "got {err:?}"
    );
    device.join().unwrap();
}
}

rt_test! {
async fn an_stls_in_answer_to_the_signature_inside_tls_is_out_of_turn() {
    // A second STLS is a protocol error wherever it comes inside the
    // session. After the signature it read as a rejected key.
    let (addr, device) = spawn_device_that_authenticates_inside_tls(AfterSignature::Stls);

    let err = failed_connect(addr, &client_config()).await;

    assert!(
        matches!(
            err,
            Error::Protocol(ProtocolError::UnexpectedCommand(Command::StartTls))
        ),
        "got {err:?}"
    );
    device.join().unwrap();
}
}

fn test_auth() -> AdbKey {
    host_key()
}

// ---------------------------------------------------------------------
// Against a real device, when one is offered
// ---------------------------------------------------------------------

/// Point `LIBADB_TLS_DEVICE` at a wireless-debugging port and ask for
/// the ignored tests to run these:
///
/// ```text
/// LIBADB_TLS_DEVICE=192.168.1.5:41234 cargo test --features tokio,tls,host-keys --test tls -- --ignored
/// ```
///
/// They need a device whose store already holds `~/.android/adbkey`,
/// which is any device that has ever been authorised over USB. Left
/// alone they show as ignored, not as passed.
#[cfg(feature = "host-keys")]
fn device_address() -> SocketAddr {
    std::env::var("LIBADB_TLS_DEVICE")
        .expect("LIBADB_TLS_DEVICE names the device's wireless-debugging port")
        .parse()
        .expect("LIBADB_TLS_DEVICE is HOST:PORT")
}

#[cfg(feature = "host-keys")]
async fn real_device_key() -> AdbKey {
    let home = std::env::var("HOME").expect("HOME");
    let dir = std::path::PathBuf::from(home).join(".android");
    // Load, never generate: a fresh key is one no device has seen.
    libadb::keys::store::load(&dir, &mut OsRng, "libadb@test")
        .expect("~/.android/adbkey, the key a USB prompt approved")
}

rt_test! {
#[cfg(feature = "host-keys")]
#[ignore = "needs a device: set LIBADB_TLS_DEVICE and pass --ignored"]
async fn a_real_device_serves_a_split_connection_over_tls() {
    let addr = device_address();
    // The split halves are a code path of their own, with their own
    // locking, so a live device is worth the trouble here even though
    // the local server already covers the unsplit one.
    let key = real_device_key().await;
    let identity = TlsIdentity::from_key(&key, &mut OsRng).unwrap();
    let tls = TlsClientConfig::adb(&identity).unwrap();

    let transport = MaybeTls::plain(rt::wrap(rt::connect(addr).await));
    let conn = Connection::<_>::connect_tls(transport, key, &[], &tls)
        .await
        .expect("the device accepts a key it was shown over USB");
    assert!(conn.transport().is_tls());

    let (mut reader, _writer) = conn.split().expect("a TLS connection splits");

    // Enough output to cross many TLS records and many ADB packets.
    let ch = reader
        .open_channel(b"shell:seq 1 20000\0")
        .await
        .expect("the device opens a shell");

    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match reader.read_channel(ch, &mut buf).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(libadb::Error::ChannelClosed) => break,
            Err(e) => panic!("read over a split TLS session failed: {e:?}"),
        }
    }

    let lines = out
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    assert_eq!(lines, 20000, "every line survived the split TLS session");
}
}
