#![cfg(any(feature = "tokio", feature = "smol"))]

//! A device that says what it has to say and goes. However the host
//! reads, all of it comes back in the order it was sent, and only then
//! the end of the channel or of the connection: an OKAY nobody is left
//! to receive costs a read nothing. Real sockets, because what a write
//! to a peer that hung up does is the kernel's to say.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use libadb::channel::ChannelId;
use libadb::{Connection, Error};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/common.rs"]
mod common;

/// Packets the device sends, at a size [`FakeDevice`] takes.
const PACKET: usize = 4096;
const PACKETS: usize = 8;
/// A read too small for a packet, and one a packet fits.
const SMALL: usize = 1000;
const WHOLE: usize = PACKET;

/// What the device sends, in which no two packets look alike, so a gap
/// or a swap shows.
fn sent() -> Vec<u8> {
    (0..PACKET * PACKETS).map(|i| (i % 251) as u8).collect()
}

#[derive(Clone, Copy)]
enum Ack {
    Delayed,
    Classic,
}

/// Whether the device closes the channel before it hangs up.
#[derive(Clone, Copy)]
enum Goes {
    ClosingTheChannel,
    Abruptly,
}

/// A connection to a device that accepts `svc:` and then sends all of
/// [`sent`] and goes; `open` is what the host opens it with. The device
/// is gone by the time this returns, so nothing the host reads can come
/// before an OKAY it sends has failed.
async fn with_device_gone<C>(
    ack: Ack,
    goes: Goes,
    open: impl AsyncFnOnce(Connection<rt::AdbTransport>) -> (C, ChannelId),
) -> (C, ChannelId) {
    let device = match ack {
        Ack::Delayed => FakeDevice::new()
            .banner(b"device::features=delayed_ack".to_vec())
            .delayed_ack(64 * 1024),
        Ack::Classic => FakeDevice::new(),
    };
    let banner: &[u8] = match ack {
        Ack::Delayed => b"host::features=delayed_ack",
        Ack::Classic => b"host::features=",
    };
    let (conn, device) = session(device, banner, move |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        for packet in sent().chunks(PACKET) {
            ch.send_write(packet).await;
        }
        if matches!(goes, Goes::ClosingTheChannel) {
            ch.send_close().await;
        }
        s.delivered().await;
    })
    .await;
    let opened = open(conn).await;
    rt::within("the device", rt::join(device)).await;
    opened
}

/// Read `ch` through `$source`, `$size` bytes at a time, until the call
/// fails: what came back, and what it failed with.
macro_rules! read_until_it_fails {
    ($source:expr, $ch:expr, $size:expr) => {{
        let mut got = Vec::new();
        let mut buf = [0u8; $size];
        let err = loop {
            match rt::within("a read", $source.read_channel($ch, &mut buf)).await {
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => break e,
            }
        };
        (got, err)
    }};
}

/// `Reader::run` takes everything in and ends; the reads come after.
async fn read_after_run(ack: Ack, goes: Goes, size: fn() -> usize) {
    let ((reader, writer), ch) = with_device_gone(ack, goes, async |conn| {
        let (mut reader, writer) = conn.split().unwrap();
        let ch = reader.open_channel(b"svc:\0").await.unwrap();
        ((reader, writer), ch)
    })
    .await;
    rt::within("run", rt::join(rt::spawn(reader.run())))
        .await
        .unwrap_err();

    let mut got = Vec::new();
    let mut buf = vec![0u8; size()];
    let err = loop {
        match rt::within("a read", writer.read_channel(ch, &mut buf)).await {
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => break e,
        }
    };
    assert!(
        got == sent(),
        "got {} bytes, out of order or short",
        got.len()
    );
    match goes {
        Goes::ClosingTheChannel => assert!(matches!(err, Error::ChannelClosed), "got {err:?}"),
        Goes::Abruptly => assert!(matches!(err, Error::Disconnected), "got {err:?}"),
    }
}

rt_test! {
async fn run_delayed_ack_with_a_close() {
    read_after_run(Ack::Delayed, Goes::ClosingTheChannel, || SMALL).await;
}
}

rt_test! {
async fn run_delayed_ack_with_no_close() {
    read_after_run(Ack::Delayed, Goes::Abruptly, || SMALL).await;
}
}

rt_test! {
async fn run_classic_ack_with_a_close() {
    read_after_run(Ack::Classic, Goes::ClosingTheChannel, || SMALL).await;
}
}

rt_test! {
async fn run_classic_ack_with_no_close() {
    read_after_run(Ack::Classic, Goes::Abruptly, || SMALL).await;
}
}

/// The reader takes each packet in as it reads, with the rest still on
/// the socket when its OKAY fails.
async fn read_through_the_reader(ack: Ack, goes: Goes) {
    let ((mut reader, _writer), ch) = with_device_gone(ack, goes, async |conn| {
        let (mut reader, writer) = conn.split().unwrap();
        let ch = reader.open_channel(b"svc:\0").await.unwrap();
        ((reader, writer), ch)
    })
    .await;

    let (got, err) = read_until_it_fails!(reader, ch, WHOLE);
    assert!(
        got == sent(),
        "got {} bytes, out of order or short",
        got.len()
    );
    match goes {
        Goes::ClosingTheChannel => assert!(matches!(err, Error::ChannelClosed), "got {err:?}"),
        Goes::Abruptly => assert!(matches!(err, Error::UnexpectedEof), "got {err:?}"),
    }
}

rt_test! {
async fn reader_delayed_ack_with_a_close() {
    read_through_the_reader(Ack::Delayed, Goes::ClosingTheChannel).await;
}
}

rt_test! {
async fn reader_delayed_ack_with_no_close() {
    read_through_the_reader(Ack::Delayed, Goes::Abruptly).await;
}
}

rt_test! {
async fn reader_classic_ack_with_a_close() {
    read_through_the_reader(Ack::Classic, Goes::ClosingTheChannel).await;
}
}

rt_test! {
async fn reader_classic_ack_with_no_close() {
    read_through_the_reader(Ack::Classic, Goes::Abruptly).await;
}
}

/// A `Connection` has only the socket to read, so the same goes for
/// it, both for a packet that fits the read and for one that does not.
macro_rules! read_through_the_connection {
    ($ack:expr, $goes:expr, $size:expr) => {{
        let (mut conn, ch) = with_device_gone($ack, $goes, async |mut conn| {
            let ch = conn.open_channel(b"svc:\0").await.unwrap();
            (conn, ch)
        })
        .await;

        let (got, err) = read_until_it_fails!(conn, ch, $size);
        assert!(
            got == sent(),
            "got {} bytes, out of order or short",
            got.len()
        );
        match $goes {
            Goes::ClosingTheChannel => {
                assert!(matches!(err, Error::ChannelClosed), "got {err:?}")
            }
            Goes::Abruptly => assert!(matches!(err, Error::UnexpectedEof), "got {err:?}"),
        }
    }};
}

// A write that times out on a socket the device has stopped reading
// desynchronizes the connection, which says nothing about what it had
// delivered by then.
rt_test! {
async fn a_write_given_up_on_leaves_what_arrived_readable() {
    const TAIL: usize = 100;
    let done = Arc::new(AtomicBool::new(false));
    let device_done = Arc::clone(&done);
    let device = FakeDevice::new()
        .banner(b"device::features=delayed_ack".to_vec())
        .delayed_ack(1 << 30);
    let (conn, device) = session(device, b"host::features=delayed_ack", move |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        for packet in sent().chunks(PACKET) {
            ch.send_write(packet).await;
        }
        while !device_done.load(Ordering::Relaxed) {
            rt::sleep_ms(5).await;
        }
    })
    .await;
    let (reader, writer) = conn.split().unwrap();
    let _run = rt::spawn(reader.run());
    let ch = writer.open_channel(b"svc:\0").await.unwrap();

    // Reading into the last packet says all of them were dispatched.
    let mut got = vec![0u8; PACKET * PACKETS - TAIL];
    let mut filled = 0;
    while filled < got.len() {
        filled += rt::within("a read", writer.read_channel(ch, &mut got[filled..])).await.unwrap();
    }

    let too_much = vec![0u8; 64 * 1024 * 1024];
    let written = rt::timeout_ms(200, writer.write_channel(ch, &too_much)).await;
    assert!(written.is_none(), "the socket took {} bytes", too_much.len());
    let err = writer.write_channel(ch, b"more").await.unwrap_err();
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");

    let (tail, err) = read_until_it_fails!(writer, ch, TAIL);
    got.extend_from_slice(&tail);
    assert!(got == sent(), "got {} bytes, out of order or short", got.len());
    assert!(matches!(err, Error::Desynchronized), "got {err:?}");

    done.store(true, Ordering::Relaxed);
    rt::within("the device", rt::join(device)).await;
}
}

rt_test! {
async fn connection_delayed_ack_with_a_close() {
    read_through_the_connection!(Ack::Delayed, Goes::ClosingTheChannel, WHOLE);
}
}

rt_test! {
async fn connection_delayed_ack_with_a_close_in_small_reads() {
    read_through_the_connection!(Ack::Delayed, Goes::ClosingTheChannel, SMALL);
}
}

rt_test! {
async fn connection_delayed_ack_with_no_close() {
    read_through_the_connection!(Ack::Delayed, Goes::Abruptly, WHOLE);
}
}

rt_test! {
async fn connection_delayed_ack_with_no_close_in_small_reads() {
    read_through_the_connection!(Ack::Delayed, Goes::Abruptly, SMALL);
}
}

rt_test! {
async fn connection_classic_ack_with_a_close() {
    read_through_the_connection!(Ack::Classic, Goes::ClosingTheChannel, WHOLE);
}
}

rt_test! {
async fn connection_classic_ack_with_a_close_in_small_reads() {
    read_through_the_connection!(Ack::Classic, Goes::ClosingTheChannel, SMALL);
}
}

rt_test! {
async fn connection_classic_ack_with_no_close() {
    read_through_the_connection!(Ack::Classic, Goes::Abruptly, WHOLE);
}
}

rt_test! {
async fn connection_classic_ack_with_no_close_in_small_reads() {
    read_through_the_connection!(Ack::Classic, Goes::Abruptly, SMALL);
}
}
