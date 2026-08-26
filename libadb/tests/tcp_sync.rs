#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::error::SyncError;
use libadb::sync;
use libadb::Error;

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeChannel, FakeDevice};

#[path = "common/common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Tests: sync protocol (stat, list, recv, send)
// ---------------------------------------------------------------------------

fn sync_header(id: &[u8; 4], arg: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(id);
    out[4..8].copy_from_slice(&arg.to_le_bytes());
    out
}

fn sync_msg(id: &[u8; 4], arg: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&sync_header(id, arg));
    out.extend_from_slice(payload);
    out
}

fn encode_stat_v2_rest(mode: u32, uid: u32, gid: u32, size: u64, mtime: i64) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[16..20].copy_from_slice(&mode.to_le_bytes());
    b[24..28].copy_from_slice(&uid.to_le_bytes());
    b[28..32].copy_from_slice(&gid.to_le_bytes());
    b[32..40].copy_from_slice(&size.to_le_bytes());
    b[48..56].copy_from_slice(&mtime.to_le_bytes());
    b
}

/// Expect a sync request WRTE with the given 4-byte id and path payload.
/// adbd terminates a LIST with a full `dent_v1` whose id is DONE, not a
/// bare 8-byte header — see `do_list` in file_sync_service.cpp.
fn list_done_v1() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"DONE");
    v.extend_from_slice(&[0u8; 16]); // mode, size, time, namelen
    v
}

/// Same for LIS2, where the record is a `dent_v2` (76 bytes).
fn list_done_v2() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"DONE");
    v.extend_from_slice(&[0u8; 72]);
    v
}

fn dent_v2(name: &[u8], mode: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"DNT2");
    v.extend_from_slice(&0u32.to_le_bytes()); // error
    v.extend_from_slice(&0u64.to_le_bytes()); // dev
    v.extend_from_slice(&0u64.to_le_bytes()); // ino
    v.extend_from_slice(&mode.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // nlink
    v.extend_from_slice(&0u32.to_le_bytes()); // uid
    v.extend_from_slice(&0u32.to_le_bytes()); // gid
    v.extend_from_slice(&0u64.to_le_bytes()); // size
    v.extend_from_slice(&0i64.to_le_bytes()); // atime
    v.extend_from_slice(&0i64.to_le_bytes()); // mtime
    v.extend_from_slice(&0i64.to_le_bytes()); // ctime
    v.extend_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend_from_slice(name);
    v
}

async fn expect_sync_req(ch: &mut FakeChannel<'_>, id: &[u8; 4], path: &[u8]) {
    let req = ch.expect_write_ack().await;
    assert_eq!(&req[..4], id);
    assert_eq!(&req[8..], path);
}

/// Expect the client's `QUIT` WRTE followed by a channel close.
async fn expect_sync_quit(ch: &mut FakeChannel<'_>) {
    assert_eq!(&ch.expect_write_ack().await[..4], b"QUIT");
    ch.expect_close().await;
}

rt_test! {
async fn sync_stat_v1_returns_decoded_fields() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"STAT", b"/file").await;

        let mut body = [0u8; 16];
        body[0..4].copy_from_slice(b"STAT");
        body[4..8].copy_from_slice(&0o100644u32.to_le_bytes());
        body[8..12].copy_from_slice(&42u32.to_le_bytes());
        body[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        ch.send_write(&body).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 128];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let stat = sync.stat("/file").await.unwrap();
    assert_eq!(stat.mode, 0o100644);
    assert_eq!(stat.size, 42);
    assert_eq!(stat.mtime, 1_700_000_000);

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_stat_v2_returns_full_metadata() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"STA2", b"/dir").await;

        let body = encode_stat_v2_rest(0o40755, 1000, 1000, 4096, 1_700_000_000);
        ch.send_write(&sync_msg(b"STA2", 0, &body)).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let stat = sync.stat_v2("/dir").await.unwrap();
    assert_eq!(stat.error, 0);
    assert_eq!(stat.mode, 0o40755);
    assert_eq!(stat.uid, 1000);
    assert_eq!(stat.size, 4096);
    assert_eq!(stat.mtime, 1_700_000_000);

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_stat_v2_maps_remote_errno_to_sync_error() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        ch.expect_write_ack().await;

        let body = encode_stat_v2_rest(0, 0, 0, 0, 0);
        ch.send_write(&sync_msg(b"STA2", 2, &body)).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let err = sync.stat_v2("/missing").await.unwrap_err();
    assert!(matches!(err, Error::Sync(SyncError::RemoteErrno(2))));

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_list_v1_returns_entries_until_done() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"LIST", b"/dir").await;

        let mut stream = Vec::new();
        for (name, mode, size) in [(&b"a.txt"[..], 0o100644u32, 10u32), (&b"sub"[..], 0o40755, 0)] {
            stream.extend_from_slice(b"DENT");
            stream.extend_from_slice(&mode.to_le_bytes());
            stream.extend_from_slice(&size.to_le_bytes());
            stream.extend_from_slice(&1_700_000_000u32.to_le_bytes());
            stream.extend_from_slice(&(name.len() as u32).to_le_bytes());
            stream.extend_from_slice(name);
        }
        stream.extend_from_slice(&list_done_v1());
        ch.send_write(&stream).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let entries = sync.list("/dir").await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, b"a.txt");
    assert_eq!(entries[0].mode, 0o100644);
    assert_eq!(entries[0].size, 10);
    assert_eq!(entries[1].name, b"sub");
    assert_eq!(entries[1].mode, 0o40755);

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_recv_v1_concatenates_data_chunks_until_done() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"RECV", b"/file").await;

        let mut stream = Vec::new();
        stream.extend_from_slice(&sync_msg(b"DATA", 5, b"hello"));
        stream.extend_from_slice(&sync_msg(b"DATA", 6, b" world"));
        stream.extend_from_slice(&sync_header(b"DONE", 0));
        ch.send_write(&stream).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let data = sync.recv("/file").await.unwrap();
    assert_eq!(data, b"hello world");

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_send_v1_sends_start_data_done_and_reads_okay() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"SEND", b"/upload,420").await;
        expect_sync_req(&mut ch, b"DATA", b"hi").await;

        let done = ch.expect_write_ack().await;
        assert_eq!(&done[..4], b"DONE");
        assert_eq!(u32::from_le_bytes(done[4..8].try_into().unwrap()), 42);

        ch.send_write(&sync_header(b"OKAY", 0)).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    sync.send("/upload", 0o644, 42, b"hi").await.unwrap();

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_fail_response_surfaces_device_message() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        ch.expect_write_ack().await;

        ch.send_write(&sync_msg(b"FAIL", 14, b"no such device"))
            .await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let err = sync.stat("/gone").await.unwrap_err();
    let Error::Sync(SyncError::Failed(msg)) = err else {
        panic!("expected Sync(Failed), got {err:?}");
    };
    assert_eq!(msg, b"no such device");

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_quit_sends_quit_then_closes_channel() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        let quit = ch.expect_write_ack().await;
        assert_eq!(&quit[..4], b"QUIT");
        assert_eq!(u32::from_le_bytes(quit[4..8].try_into().unwrap()), 0);

        ch.expect_close().await;
    })
    .await;

    let mut buf = [0u8; 64];
    let sync = sync::open(&mut conn, &mut buf).await.unwrap();
    sync.quit().await.unwrap();

    rt::join(device).await;
}
}

rt_test! {
async fn sync_session_survives_a_list_v1() {
    // Real adbd closes a LIST with a whole dent record; consuming only
    // its 8-byte head leaves 12 bytes in the stream and derails the
    // next request in the same session.
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"LIST", b"/dir").await;
        ch.send_write(&list_done_v1()).await;
        ch.expect_ack().await;

        expect_sync_req(&mut ch, b"STAT", b"/dir").await;
        let mut stat = Vec::new();
        stat.extend_from_slice(b"STAT");
        stat.extend_from_slice(&0o40755u32.to_le_bytes());
        stat.extend_from_slice(&0u32.to_le_bytes());
        stat.extend_from_slice(&0u32.to_le_bytes());
        ch.send_write(&stat).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    assert!(sync.list("/dir").await.unwrap().is_empty());

    let st = sync.stat("/dir").await.expect("stat after list");
    assert_eq!(st.mode, 0o40755);

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_session_survives_a_list_v2() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        expect_sync_req(&mut ch, b"LIS2", b"/dir").await;
        let mut stream = dent_v2(b"a.txt", 0o100644);
        stream.extend_from_slice(&list_done_v2());
        ch.send_write(&stream).await;
        ch.expect_ack().await;

        expect_sync_req(&mut ch, b"STA2", b"/dir").await;
        let mut stat = Vec::new();
        stat.extend_from_slice(b"STA2");
        stat.extend_from_slice(&[0u8; 68]);
        ch.send_write(&stat).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let entries = sync.list_v2("/dir").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"a.txt");

    sync.stat_v2("/dir").await.expect("stat_v2 after list_v2");

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}
