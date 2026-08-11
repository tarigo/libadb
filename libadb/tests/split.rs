#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::protocol::command::{CMD_CLSE, CMD_OKAY, CMD_OPEN, CMD_WRTE};
use libadb::{Connection, Error};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, wrap, FakeDevice, TestAuth};

macro_rules! rt_test {
    ($(#[$attr:meta])* async fn $name:ident() $body:block) => {
        $(#[$attr])*
        #[test]
        fn $name() {
            $crate::rt::block_on(async move $body);
        }
    };
}

const DA_BANNER: &[u8] = b"device::features=delayed_ack";
const DA_MAX_PAYLOAD: u32 = 16;

// ---------------------------------------------------------------------------
// Test 1 — Concurrent bidirectional traffic on a single split connection.
//
// Main task opens a channel, moves the Reader into a background task that
// loops read_channel until CLSE, and from the foreground drives the
// cloneable Writer. Exercises:
//  * Reader dispatching OKAYs for the Writer's WRTEs while buffering
//    WRTEs from the device,
//  * Writer issuing sends that cross the await boundary with the Reader,
//  * clean shutdown via close_channel + remote CLSE.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_concurrent_write_and_read() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;

        for i in 0..3u8 {
            ch.send_write(&[b'D', b'0' + i]).await;
        }

        let mut client_wrtes = 0;
        let mut our_okays = 0;
        while client_wrtes < 3 || our_okays < 3 {
            let (hdr, _) = ch.recv_any().await;
            match hdr.command {
                CMD_WRTE => {
                    ch.ack(0).await;
                    client_wrtes += 1;
                }
                CMD_OKAY => our_okays += 1,
                c => panic!("unexpected command: 0x{c:08X}"),
            }
        }

        ch.expect_close().await;
        ch.send_close().await;
    })
    .await;

    let (mut reader, writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    let reader_task = rt::spawn(async move {
        let mut collected: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut buf = [0u8; 64];
            match reader.read_channel(ch, &mut buf).await {
                Ok(n) => collected.push(buf[..n].to_vec()),
                Err(Error::ChannelClosed) => break,
                Err(e) => panic!("read_channel: {e:?}"),
            }
        }
        collected
    });

    for i in 0..3u8 {
        let payload = [b'C', b'0' + i];
        rt::timeout_ms(5000, writer.write_channel(ch, &payload))
            .await
            .expect("write_channel timed out")
            .unwrap();
    }

    rt::timeout_ms(5000, writer.close_channel(ch))
        .await
        .expect("close_channel timed out")
        .unwrap();

    let received = rt::timeout_ms(5000, rt::join(reader_task))
        .await
        .expect("reader task hung");

    assert_eq!(received, vec![b"D0".to_vec(), b"D1".to_vec(), b"D2".to_vec()]);
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Test 2 — Local close_channel wakes a writer parked on flow control.
//
// Legacy (no delayed-ack) mode. A first write consumes the initial
// wrte_acked=true, a second write from a cloned Writer parks. A third
// task calls close_channel — the wake issued from Writer::close_channel
// must unblock the parked write with ChannelClosed.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_close_wakes_parked_writer() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        ch.expect_write().await;
        ch.expect_close().await;
    })
    .await;

    let (mut reader, writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    let reader_task = rt::spawn(async move {
        let mut buf = [0u8; 8];
        let _ = reader.read_channel(ch, &mut buf).await;
    });

    writer.write_channel(ch, b"a").await.unwrap();

    // join2 polls parked_fut first (registers EventListener, returns
    // Pending), then closer_fut sends CLSE and notifies; the parked
    // writer re-polls with ChannelClosed. Deterministic, no sleep.
    let w2 = writer.clone();
    let parked_fut = async move { w2.write_channel(ch, b"b").await };
    let closer_fut = async { writer.close_channel(ch).await };

    let (parked_res, close_res) = rt::timeout_ms(5000, rt::join2(parked_fut, closer_fut))
        .await
        .expect("join2 timed out — parked writer was not woken");

    assert!(
        matches!(parked_res, Err(Error::ChannelClosed)),
        "parked writer should surface ChannelClosed, got {parked_res:?}"
    );
    close_res.unwrap();

    let _ = rt::timeout_ms(2000, rt::join(reader_task)).await;
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Test 3 — Remote CLSE wakes a writer parked on flow control.
//
// Reader::dispatch / Reader::read_channel both process CLSE by flipping
// the slot to Closed and waking its FlowSignal. A parked writer must
// then re-poll, observe the terminal state, and return ChannelClosed.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_remote_close_wakes_parked_writer() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        ch.expect_write().await;
        ch.send_close().await;
        ch.expect_close().await;
    })
    .await;

    let (mut reader, writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    let reader_task = rt::spawn(async move {
        let mut buf = [0u8; 8];
        reader.read_channel(ch, &mut buf).await
    });

    writer.write_channel(ch, b"a").await.unwrap();

    let w2 = writer.clone();
    let parked = rt::spawn(async move { w2.write_channel(ch, b"b").await });

    let parked_result = rt::timeout_ms(2000, rt::join(parked))
        .await
        .expect("parked writer not woken by remote CLSE");
    assert!(
        matches!(parked_result, Err(Error::ChannelClosed)),
        "parked writer should surface ChannelClosed, got {parked_result:?}"
    );

    let reader_result = rt::timeout_ms(2000, rt::join(reader_task))
        .await
        .expect("reader task hung");
    assert!(matches!(reader_result, Err(Error::ChannelClosed)));

    let _ = writer.close_channel(ch).await;
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Test 4 — Delayed-ACK with budget < max_payload still progresses.
//
// Regression test for the "split writer requires send_budget >=
// chunk_len" bug. With initial_asb = 8 and max_payload = 16, writing 24
// bytes must go out as three 8-byte WRTEs rather than hang.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_delayed_ack_partial_budget_progresses() {
    const INITIAL_ASB: u32 = 8;

    let dev = FakeDevice::new()
        .banner(DA_BANNER)
        .max_payload(DA_MAX_PAYLOAD)
        .delayed_ack(INITIAL_ASB);
    let (conn, device) = session(dev, b"host::features=delayed_ack", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;

        for i in 0..3u8 {
            let p = ch.expect_write().await;
            assert!(
                p.len() <= INITIAL_ASB as usize,
                "chunk #{i} size {} exceeded granted budget {INITIAL_ASB}",
                p.len(),
            );
            ch.ack(INITIAL_ASB).await;
        }

        ch.expect_close().await;
        ch.send_close().await;
    })
    .await;

    assert!(conn.delayed_ack());
    let (mut reader, writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    let reader_task = rt::spawn(async move {
        let mut buf = [0u8; 8];
        let _ = reader.read_channel(ch, &mut buf).await;
    });

    let data = vec![0xAAu8; (INITIAL_ASB as usize) * 3];
    rt::timeout_ms(5000, writer.write_channel(ch, &data))
        .await
        .expect("write_channel hung — partial budget not respected")
        .unwrap();

    rt::timeout_ms(2000, writer.close_channel(ch))
        .await
        .expect("close timed out")
        .unwrap();

    let _ = rt::timeout_ms(2000, rt::join(reader_task)).await;
    rt::join(device).await;
}
}

// ---------------------------------------------------------------------------
// Test 5 — Slot-table exhaustion on the split path.
//
// `Reader::open_channel` reserves a slot before sending OPEN, so when the
// table is full the caller must see `NoFreeChannels` before any wire
// traffic — the device never sees a third OPEN. Uses the low-level
// `bind()` path because `session()` pins the `MAX_CHANNELS` const to
// its default.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_open_channel_no_free_slots_when_table_is_full() {
    let (handle, addr) = FakeDevice::new().bind().await;

    let device = rt::spawn(async move {
        let mut s = handle.accept().await;
        let mut pairs: Vec<(u32, u32)> = Vec::new();

        for did in [100u32, 200u32] {
            let (hdr, _) = s.expect(CMD_OPEN).await;
            let cid = hdr.arg0;
            pairs.push((cid, did));
            s.send(CMD_OKAY, did, cid, &[]).await;
        }

        for _ in 0..2 {
            let (hdr, _) = s.expect(CMD_CLSE).await;
            let (_, did) = pairs.iter().find(|(c, _)| *c == hdr.arg0).copied().unwrap();
            assert_eq!(hdr.arg1, did);
        }
    });

    let stream = rt::connect(addr).await;
    let conn = Connection::<_, 2>::connect_with_raw_banner(wrap(stream), TestAuth, b"host::")
        .await
        .unwrap();
    let (mut reader, writer) = conn.split().unwrap();

    let ch1 = reader.open_channel(b"svc1:\0").await.unwrap();
    let ch2 = reader.open_channel(b"svc2:\0").await.unwrap();

    let err = reader.open_channel(b"svc3:\0").await.unwrap_err();
    assert!(
        matches!(err, Error::NoFreeChannels),
        "expected NoFreeChannels, got {err:?}",
    );

    writer.close_channel(ch1).await.unwrap();
    writer.close_channel(ch2).await.unwrap();

    rt::timeout_ms(5000, rt::join(device))
        .await
        .expect("device hung");
}
}

// ---------------------------------------------------------------------------
// Test 6 — Writing to a locally-closed channel.
//
// `close_channel` clears the slot. A subsequent `write_channel` must fail
// at the credit-reservation step with `ChannelClosed` rather than pushing
// a stray WRTE onto the wire.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_write_channel_after_local_close_returns_channel_closed() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        ch.expect_close().await;
        if let Some((hdr, _)) = rt::timeout_ms(100, s.recv()).await {
            assert_ne!(hdr.command, CMD_WRTE, "no WRTE must be sent after local close");
        }
    })
    .await;

    let (mut reader, writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    writer.close_channel(ch).await.unwrap();

    let err = writer.write_channel(ch, b"stray").await.unwrap_err();
    assert!(
        matches!(err, Error::ChannelClosed),
        "expected ChannelClosed, got {err:?}",
    );

    rt::timeout_ms(5000, rt::join(device))
        .await
        .expect("device hung");
}
}

// ---------------------------------------------------------------------------
// Test 7 — Reading from a locally-closed channel.
//
// After `close_channel` clears the slot, `read_channel` must refuse
// immediately — it must not start pulling packets from the wire under
// a freed id.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_read_channel_after_local_close_returns_channel_closed() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut ch = s.accept_open(b"svc:\0").await;
        ch.expect_close().await;
    })
    .await;

    let (mut reader, writer) = conn.split().unwrap();
    let ch = reader.open_channel(b"svc:\0").await.unwrap();

    writer.close_channel(ch).await.unwrap();

    let mut buf = [0u8; 8];
    let err = rt::timeout_ms(5000, reader.read_channel(ch, &mut buf))
        .await
        .expect("read_channel hung on closed slot")
        .unwrap_err();
    assert!(
        matches!(err, Error::ChannelClosed),
        "expected ChannelClosed, got {err:?}",
    );

    rt::timeout_ms(5000, rt::join(device))
        .await
        .expect("device hung");
}
}

// ---------------------------------------------------------------------------
// Test 8 — Device rejects an OPEN by sending CLSE before OKAY.
//
// `open_channel` matches CLSE by `arg1 == local_id` and surfaces
// `ChannelClosed`; the `SlotGuard` Drop path releases the reserved slot.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_open_channel_returns_channel_closed_when_device_rejects() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let (hdr, _) = s.expect(CMD_OPEN).await;
        let client_local = hdr.arg0;
        s.send(CMD_CLSE, 0, client_local, &[]).await;
    })
    .await;

    let (mut reader, _writer) = conn.split().unwrap();

    let err = rt::timeout_ms(5000, reader.open_channel(b"svc:\0"))
        .await
        .expect("open_channel hung on device reject")
        .unwrap_err();
    assert!(
        matches!(err, Error::ChannelClosed),
        "expected ChannelClosed, got {err:?}",
    );

    rt::timeout_ms(5000, rt::join(device))
        .await
        .expect("device hung");
}
}

// ---------------------------------------------------------------------------
// Test 9 — Two cloned `Writer`s drive different channels concurrently.
//
// Proves the clone is usable from an independent task: both writes
// serialize on the shared `write_half` mutex and both complete without
// one starving the other.
// ---------------------------------------------------------------------------

rt_test! {
async fn split_two_cloned_writers_make_progress_on_different_channels() {
    let (conn, device) = session(FakeDevice::new(), b"host::", |mut s| async move {
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut next_did: u32 = 100;
        let mut open_count = 0;
        let mut close_count = 0;

        while close_count < 2 {
            let (hdr, data) = s.recv().await;
            match hdr.command {
                CMD_OPEN => {
                    let cid = hdr.arg0;
                    let did = next_did;
                    next_did += 100;
                    pairs.push((cid, did));
                    s.send(CMD_OKAY, did, cid, &[]).await;
                    open_count += 1;
                }
                CMD_WRTE => {
                    let (_, did) = pairs.iter().find(|(c, _)| *c == hdr.arg0).copied().unwrap();
                    payloads.push(data);
                    s.send(CMD_OKAY, did, hdr.arg0, &[]).await;
                }
                CMD_CLSE => close_count += 1,
                CMD_OKAY => {}
                c => panic!("unexpected command: 0x{c:08X}"),
            }
        }
        assert_eq!(open_count, 2);
        payloads
    })
    .await;

    let (mut reader, w1) = conn.split().unwrap();
    let ch1 = reader.open_channel(b"svc1:\0").await.unwrap();
    let ch2 = reader.open_channel(b"svc2:\0").await.unwrap();
    let w2 = w1.clone();

    let t1 = rt::spawn(async move {
        w1.write_channel(ch1, b"alpha").await.unwrap();
        w1.close_channel(ch1).await.unwrap();
    });
    let t2 = rt::spawn(async move {
        w2.write_channel(ch2, b"beta").await.unwrap();
        w2.close_channel(ch2).await.unwrap();
    });

    rt::timeout_ms(5000, rt::join2(rt::join(t1), rt::join(t2)))
        .await
        .expect("writers hung");

    let payloads = rt::timeout_ms(5000, rt::join(device))
        .await
        .expect("device hung");

    drop(reader);

    assert_eq!(payloads.len(), 2);
    assert!(payloads.iter().any(|p| p.as_slice() == b"alpha"));
    assert!(payloads.iter().any(|p| p.as_slice() == b"beta"));
}
}
