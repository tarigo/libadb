#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::error::SyncError;
use libadb::protocol::command::{CMD_CLSE, CMD_WRTE};
use libadb::sync::{self, FileMode, SyncFlags};
use libadb::{Error, Feature};

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeChannel, FakeDevice, FakeSession};

#[path = "common/common.rs"]
mod common;
use common::expect_missing_feature;

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

/// A device that advertises the v2 requests, and none of the flags
/// `RCV2` and `SND2` can carry.
fn v2_device() -> FakeDevice {
    FakeDevice::new().banner(b"device::features=stat_v2,ls_v2,sendrecv_v2".to_vec())
}

/// A device that advertises `features` and nothing else.
fn device_with(features: &[Feature]) -> FakeDevice {
    let names: Vec<_> = features.iter().map(Feature::wire_name).collect();
    FakeDevice::new().banner(format!("device::features={}", names.join(",")).into_bytes())
}

/// Every sync feature there is.
const ALL_SYNC_FEATURES: [Feature; 7] = [
    Feature::StatV2,
    Feature::LsV2,
    Feature::SendrecvV2,
    Feature::SendrecvV2Brotli,
    Feature::SendrecvV2Lz4,
    Feature::SendrecvV2Zstd,
    Feature::SendrecvV2DryRunSend,
];

/// Each flag, the feature it needs, and its value in adbd's `SyncFlag`.
const FLAGS: [(SyncFlags, Feature, u32); 4] = [
    (SyncFlags::BROTLI, Feature::SendrecvV2Brotli, 1),
    (SyncFlags::LZ4, Feature::SendrecvV2Lz4, 2),
    (SyncFlags::ZSTD, Feature::SendrecvV2Zstd, 4),
    (
        SyncFlags::DRY_RUN,
        Feature::SendrecvV2DryRunSend,
        0x8000_0000,
    ),
];

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

/// What the host wrote on a sync channel, read as adbd reads it:
/// `ReadFdExactly` sees a byte stream, so the WRTEs the host cut it into
/// do not show.
struct DaemonStream<'c, 's> {
    ch: &'c mut FakeChannel<'s>,
    /// What arrived past the last read.
    ahead: Vec<u8>,
}

impl<'c, 's> DaemonStream<'c, 's> {
    fn new(ch: &'c mut FakeChannel<'s>) -> Self {
        Self {
            ch,
            ahead: Vec::new(),
        }
    }

    /// Acknowledge WRTEs until `n` bytes are in, and take exactly those.
    async fn read(&mut self, n: usize) -> Vec<u8> {
        while self.ahead.len() < n {
            let payload = self.ch.expect_write_ack().await;
            self.ahead.extend_from_slice(&payload);
        }
        let rest = self.ahead.split_off(n);
        std::mem::replace(&mut self.ahead, rest)
    }

    /// An eight-byte id and word: a `SyncRequest`, a `sync_recv_v2`, or
    /// the head of a `sync_data`.
    async fn read_head(&mut self) -> ([u8; 4], u32) {
        let head = self.read(8).await;
        (head[..4].try_into().unwrap(), le32(&head[4..]))
    }

    /// A request as `handle_sync_command` reads it: the `SyncRequest`,
    /// then as many bytes of name as its `path_length` says.
    async fn read_request(&mut self) -> ([u8; 4], Vec<u8>) {
        let (id, path_length) = self.read_head().await;
        (id, self.read(path_length as usize).await)
    }

    /// An `RCV2` for `path`, as `do_recv_v2` reads it after the request.
    /// Returns its flags.
    async fn expect_rcv2(&mut self, path: &[u8]) -> u32 {
        let (id, name) = self.read_request().await;
        assert_eq!(&id, b"RCV2");
        assert_eq!(name, path, "path_length must cover the path alone");

        let (setup_id, flags) = self.read_head().await;
        assert_eq!(&setup_id, b"RCV2");
        flags
    }

    /// An `SND2` for `path`, as `do_send_v2` reads it after the request.
    /// Returns its mode and flags.
    async fn expect_snd2(&mut self, path: &[u8]) -> (u32, u32) {
        let (id, name) = self.read_request().await;
        assert_eq!(&id, b"SND2");
        assert_eq!(name, path, "path_length must cover the path alone");

        let setup = self.read(12).await;
        assert_eq!(&setup[..4], b"SND2");
        (le32(&setup[4..8]), le32(&setup[8..12]))
    }

    /// The rest of a push, as `handle_send_file_data` reads it: `data`
    /// in one `DATA`, and a `DONE` carrying `mtime`.
    async fn expect_pushed(&mut self, data: &[u8], mtime: u32) {
        let (id, size) = self.read_head().await;
        assert_eq!(&id, b"DATA");
        assert_eq!(self.read(size as usize).await, data);

        let (id, timestamp) = self.read_head().await;
        assert_eq!(&id, b"DONE");
        assert_eq!(timestamp, mtime);
    }

    /// `QUIT` with nothing behind it, then a channel close.
    async fn expect_quit(&mut self) {
        let (id, name) = self.read_request().await;
        assert_eq!(&id, b"QUIT");
        assert!(name.is_empty());
        assert!(self.ahead.is_empty(), "bytes past QUIT: {:?}", self.ahead);
        self.ch.expect_close().await;
    }

    /// Answer in one WRTE and take the host's OKAY for it.
    async fn reply(&mut self, bytes: &[u8]) {
        self.ch.send_write(bytes).await;
        self.ch.expect_ack().await;
    }

    /// Answer a pull with `data`, in the `DATA` and `DONE` `recv_impl`
    /// writes.
    async fn reply_pulled(&mut self, data: &[u8]) {
        let mut stream = sync_msg(b"DATA", data.len() as u32, data);
        stream.extend_from_slice(&sync_header(b"DONE", 0));
        self.reply(&stream).await;
    }

    /// Answer a `STAT` with a regular file of `size` bytes.
    async fn reply_stat(&mut self, size: u32) {
        let mut body = Vec::new();
        body.extend_from_slice(b"STAT");
        body.extend_from_slice(&0o100644u32.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        self.reply(&body).await;
    }
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

/// The device of a host whose calls are all refused before they reach
/// the wire: the first thing it reads is the `STAT` for `/after` the host
/// makes to prove the session still works, and then `QUIT`.
async fn expect_only_a_stat_of_after(mut s: FakeSession) {
    let mut ch = s.accept_open(b"sync:\0").await;
    let mut adbd = DaemonStream::new(&mut ch);

    let (id, name) = adbd.read_request().await;
    assert_eq!(&id, b"STAT");
    assert_eq!(name, b"/after");
    adbd.reply_stat(7).await;

    adbd.expect_quit().await;
}

fn expect_invalid_flags<T, E: core::fmt::Debug>(result: Result<T, Error<E>>, flags: SyncFlags) {
    let Err(err) = result else {
        panic!("expected Err(InvalidFlags({flags:?})), got Ok");
    };
    assert!(
        matches!(err, Error::Sync(SyncError::InvalidFlags(f)) if f == flags),
        "expected InvalidFlags({flags:?}), got {err:?}",
    );
}

fn expect_invalid_path<T, E: core::fmt::Debug>(result: Result<T, Error<E>>) {
    let Err(err) = result else {
        panic!("expected Err(InvalidPath), got Ok");
    };
    assert!(
        matches!(err, Error::Sync(SyncError::InvalidPath)),
        "expected InvalidPath, got {err:?}",
    );
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
    assert_eq!(stat.mode, FileMode(0o100644));
    assert_eq!(stat.size, 42);
    assert_eq!(stat.mtime, 1_700_000_000);

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_stat_v2_returns_full_metadata() {
    let (mut conn, device) = session(v2_device(), b"host::features=", |mut s| async move {
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
    assert_eq!(stat.mode, FileMode(0o40755));
    assert_eq!(stat.uid, 1000);
    assert_eq!(stat.size, 4096);
    assert_eq!(stat.mtime, 1_700_000_000);

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_stat_v2_maps_remote_errno_to_sync_error() {
    let (mut conn, device) = session(v2_device(), b"host::features=", |mut s| async move {
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
async fn sync_v2_requests_need_their_features() {
    // The default banner lists no features, so every v2 call fails
    // before it writes: the one request the device sees is QUIT.
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;
        expect_sync_quit(&mut ch).await;
    })
    .await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    expect_missing_feature(sync.stat_v2("/f").await, Feature::StatV2);
    expect_missing_feature(sync.list_v2("/d").await, Feature::LsV2);
    expect_missing_feature(
        sync.recv_v2("/f", SyncFlags::NONE).await,
        Feature::SendrecvV2,
    );
    expect_missing_feature(
        sync.send_v2("/f", FileMode(0o100644), 0, SyncFlags::NONE, b"x")
            .await,
        Feature::SendrecvV2,
    );

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
    assert_eq!(entries[0].mode, FileMode(0o100644));
    assert_eq!(entries[0].size, 10);
    assert_eq!(entries[1].name, b"sub");
    assert_eq!(entries[1].mode, FileMode(0o40755));

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
    sync.send("/upload", FileMode(0o644), 42, b"hi").await.unwrap();

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

/// A device that fails a push as `handle_send_file` does: the `FAIL` as
/// soon as it knows, then on reading what the host sends, for as long
/// as that takes it to reach `DONE`, and only then the end of the
/// service. From there on a WRTE reaches nobody.
async fn fail_the_push(mut s: FakeSession, id: &[u8; 4], text: &[u8]) {
    let mut ch = s.accept_open(b"sync:\0").await;
    let send = ch.expect_write_ack().await;
    assert_eq!(&send[..4], id);
    ch.send_write(&sync_msg(b"FAIL", text.len() as u32, text))
        .await;

    let mut read = Vec::new();
    while !read.windows(4).any(|id| id == b"DONE") {
        let (header, payload) = ch.recv_any().await;
        if header.command == CMD_WRTE {
            ch.ack(payload.len() as u32).await;
            read.extend_from_slice(&payload);
        }
    }
    ch.send_close().await;

    while ch.recv_any().await.0.command != CMD_CLSE {}
}

/// The text has to reach the host however its writes fall around the
/// `FAIL`, and the session end with a `quit` that may find the device
/// gone from the channel.
async fn a_failed_push_gets_the_devices_text(device: FakeDevice, banner: &'static [u8], v2: bool) {
    const TEXT: &[u8] = b"couldn't create file: Read-only file system";
    let id = if v2 { b"SND2" } else { b"SEND" };
    let (mut conn, device) = session(device, banner, move |s| fail_the_push(s, id, TEXT)).await;

    let mut buf = [0u8; 256];
    let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
    let data = vec![0x5a; 4 * 1024];
    let mode = FileMode(0o644);
    let pushed = if v2 {
        sync.send_v2("/x", mode, 0, SyncFlags::NONE, &data).await
    } else {
        sync.send("/x", mode, 0, &data).await
    };
    let err = pushed.unwrap_err();
    let Error::Sync(SyncError::Failed(text)) = err else {
        panic!("expected Sync(Failed), got {err:?}");
    };
    assert_eq!(text, TEXT);

    sync.quit().await.unwrap();
    rt::within("the device", rt::join(device)).await;
}

rt_test! {
async fn sync_failed_push_gets_the_devices_text_without_delayed_ack() {
    a_failed_push_gets_the_devices_text(FakeDevice::new(), b"host::features=", false).await;
}
}

rt_test! {
async fn sync_failed_push_gets_the_devices_text_with_delayed_ack() {
    let device = FakeDevice::new()
        .banner(b"device::features=delayed_ack".to_vec())
        .delayed_ack(1024);
    a_failed_push_gets_the_devices_text(device, b"host::features=delayed_ack", false).await;
}
}

rt_test! {
async fn sync_failed_v2_push_gets_the_devices_text_without_delayed_ack() {
    a_failed_push_gets_the_devices_text(v2_device(), b"host::features=", true).await;
}
}

rt_test! {
async fn sync_failed_v2_push_gets_the_devices_text_with_delayed_ack() {
    let device = FakeDevice::new()
        .banner(b"device::features=sendrecv_v2,delayed_ack".to_vec())
        .delayed_ack(1024);
    a_failed_push_gets_the_devices_text(device, b"host::features=delayed_ack", true).await;
}
}

rt_test! {
async fn sync_fail_longer_than_the_buffer_is_truncated_not_masked() {
    let (mut conn, device) = session(FakeDevice::new(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        ch.expect_write_ack().await;

        let long = [b'x'; 600];
        ch.send_write(&sync_msg(b"FAIL", 600, &long)).await;
        ch.expect_ack().await;

        // The follow-up request only parses right if the parser is
        // positioned after the whole 600-byte body.
        expect_sync_req(&mut ch, b"STAT", b"/ok").await;
        let mut body = [0u8; 16];
        body[0..4].copy_from_slice(b"STAT");
        body[4..8].copy_from_slice(&0o100644u32.to_le_bytes());
        body[8..12].copy_from_slice(&7u32.to_le_bytes());
        body[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        ch.send_write(&body).await;
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
    assert_eq!(msg.len(), 256, "kept exactly what the buffer holds");
    assert!(msg.iter().all(|&b| b == b'x'));

    // The overflow was drained, not left in the stream: the next
    // response-reading operation parses from a clean position.
    let st = sync.stat("/ok").await.unwrap();
    assert_eq!(st.size, 7);

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
    assert_eq!(st.mode, FileMode(0o40755));

    sync.quit().await.unwrap();
    rt::join(device).await;
}
}

rt_test! {
async fn sync_session_survives_a_list_v2() {
    let (mut conn, device) = session(v2_device(), b"host::features=", |mut s| async move {
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

/// A pull, a push and a request after them on one session, against a
/// device that reads what adbd reads: a v2 setup missing its id leaves
/// it waiting on a pull and reading the next message as flags on a push.
/// `buf` is the session's buffer, which decides how the requests go out.
async fn v2_transfers_with_a_request_after_them(buf: &mut [u8]) {
    let (mut conn, device) = session(v2_device(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;
        let mut adbd = DaemonStream::new(&mut ch);

        assert_eq!(adbd.expect_rcv2(b"/sdcard/in").await, 0);
        adbd.reply_pulled(b"hello").await;

        let (mode, flags) = adbd.expect_snd2(b"/sdcard/out").await;
        assert_eq!(mode, 0o100644);
        assert_eq!(flags, 0);
        adbd.expect_pushed(b"hi", 42).await;
        adbd.reply(&sync_header(b"OKAY", 0)).await;

        let (id, name) = adbd.read_request().await;
        assert_eq!(&id, b"STAT");
        assert_eq!(name, b"/sdcard/after");
        adbd.reply_stat(7).await;

        adbd.expect_quit().await;
    })
    .await;

    rt::within("the v2 transfers", async {
        let mut sync = sync::open(&mut conn, buf).await.unwrap();
        let pulled = sync.recv_v2("/sdcard/in", SyncFlags::NONE).await.unwrap();
        assert_eq!(pulled, b"hello");

        sync.send_v2(
            "/sdcard/out",
            FileMode(0o100644),
            42,
            SyncFlags::NONE,
            b"hi",
        )
        .await
        .unwrap();

        let st = sync.stat("/sdcard/after").await.unwrap();
        assert_eq!(st.size, 7);

        sync.quit().await.unwrap();
        rt::join(device).await;
    })
    .await;
}

rt_test! {
async fn sync_v2_transfers_send_the_setup_adbd_reads() {
    v2_transfers_with_a_request_after_them(&mut [0u8; 256]).await;
}
}

rt_test! {
async fn sync_v2_setup_too_long_for_the_buffer_arrives_whole() {
    // 24 bytes hold every reply here but neither request with its setup,
    // so both take the way out that writes the parts one by one.
    v2_transfers_with_a_request_after_them(&mut [0u8; 24]).await;
}
}

rt_test! {
async fn sync_v2_setup_goes_out_with_its_request_in_one_write() {
    // adbd's client writes them together too: `SendRecv2` and `SendSend2`
    // make one WriteFdExactly of the request, the path and the setup.
    let (mut conn, device) = session(v2_device(), b"host::features=", |mut s| async move {
        let mut ch = s.accept_open(b"sync:\0").await;

        let mut pull = sync_msg(b"RCV2", 2, b"/f");
        pull.extend_from_slice(&sync_header(b"RCV2", 0));
        assert_eq!(ch.expect_write_ack().await, pull);
        ch.send_write(&sync_header(b"DONE", 0)).await;
        ch.expect_ack().await;

        let mut push = sync_msg(b"SND2", 2, b"/f");
        push.extend_from_slice(&sync_msg(b"SND2", 0o100644, &0u32.to_le_bytes()));
        assert_eq!(ch.expect_write_ack().await, push);
        expect_sync_req(&mut ch, b"DONE", b"").await;
        ch.send_write(&sync_header(b"OKAY", 0)).await;
        ch.expect_ack().await;

        expect_sync_quit(&mut ch).await;
    })
    .await;

    rt::within("the v2 transfers", async {
        let mut buf = [0u8; 256];
        let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
        sync.recv_v2("/f", SyncFlags::NONE).await.unwrap();
        sync.send_v2("/f", FileMode(0o100644), 0, SyncFlags::NONE, b"")
            .await
            .unwrap();

        sync.quit().await.unwrap();
        rt::join(device).await;
    })
    .await;
}
}

rt_test! {
async fn sync_flag_needs_its_own_feature_before_anything_is_sent() {
    for (flag, feature, _) in FLAGS {
        // Everything else is advertised, so the one feature left out is
        // the only thing that can stop the request.
        let others: Vec<_> = ALL_SYNC_FEATURES
            .into_iter()
            .filter(|f| *f != feature)
            .collect();
        let (mut conn, device) = session(
            device_with(&others),
            b"host::features=",
            expect_only_a_stat_of_after,
        )
        .await;

        let mut buf = [0u8; 256];
        let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
        if flag != SyncFlags::DRY_RUN {
            expect_missing_feature(sync.recv_v2("/f", flag).await, feature);
        }
        expect_missing_feature(
            sync.send_v2("/f", FileMode(0o100644), 0, flag, b"x").await,
            feature,
        );

        assert_eq!(sync.stat("/after").await.unwrap().size, 7);
        sync.quit().await.unwrap();
        rt::join(device).await;
    }
}
}

rt_test! {
async fn sync_flag_reaches_the_setup_of_a_device_that_takes_it() {
    for (flag, feature, bits) in FLAGS {
        // adbd has no dry-run pull.
        let pulls = flag != SyncFlags::DRY_RUN;
        let (mut conn, device) = session(
            device_with(&[Feature::SendrecvV2, feature]),
            b"host::features=",
            move |mut s| async move {
                let mut ch = s.accept_open(b"sync:\0").await;
                let mut adbd = DaemonStream::new(&mut ch);

                if pulls {
                    assert_eq!(adbd.expect_rcv2(b"/f").await, bits);
                    adbd.reply_pulled(b"x").await;
                }

                let (mode, flags) = adbd.expect_snd2(b"/f").await;
                assert_eq!(mode, 0o100644);
                assert_eq!(flags, bits);
                adbd.expect_pushed(b"x", 0).await;
                adbd.reply(&sync_header(b"OKAY", 0)).await;

                adbd.expect_quit().await;
            },
        )
        .await;

        rt::within("the flagged transfers", async {
            let mut buf = [0u8; 256];
            let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
            if pulls {
                assert_eq!(sync.recv_v2("/f", flag).await.unwrap(), b"x");
            }
            sync.send_v2("/f", FileMode(0o100644), 0, flag, b"x")
                .await
                .unwrap();

            sync.quit().await.unwrap();
            rt::join(device).await;
        })
        .await;
    }
}
}

rt_test! {
async fn sync_dry_run_goes_with_a_compression_flag_on_a_push() {
    // Refusing a dry run on a pull must not spill over to the push, where
    // `do_send_v2` reads the two flags apart.
    let (mut conn, device) = session(
        device_with(&ALL_SYNC_FEATURES),
        b"host::features=",
        |mut s| async move {
            let mut ch = s.accept_open(b"sync:\0").await;
            let mut adbd = DaemonStream::new(&mut ch);

            let (_, flags) = adbd.expect_snd2(b"/f").await;
            assert_eq!(flags, 0x8000_0004);
            adbd.expect_pushed(b"x", 0).await;
            adbd.reply(&sync_header(b"OKAY", 0)).await;

            adbd.expect_quit().await;
        },
    )
    .await;

    rt::within("the dry run", async {
        let mut buf = [0u8; 256];
        let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();
        let flags = SyncFlags::ZSTD | SyncFlags::DRY_RUN;
        sync.send_v2("/f", FileMode(0o100644), 0, flags, b"x")
            .await
            .unwrap();

        sync.quit().await.unwrap();
        rt::join(device).await;
    })
    .await;
}
}

rt_test! {
async fn sync_flags_adbd_refuses_fail_whatever_the_device_advertises() {
    // A missing feature would read as a device that could do better, and
    // no device can: `do_recv_v2` has no dry run, and `do_send_v2` and
    // `do_recv_v2` both take one compression flag.
    for banner in [device_with(&ALL_SYNC_FEATURES), FakeDevice::new()] {
        let (mut conn, device) =
            session(banner, b"host::features=", expect_only_a_stat_of_after).await;

        let mut buf = [0u8; 256];
        let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();

        for flags in [SyncFlags::DRY_RUN, SyncFlags::DRY_RUN | SyncFlags::LZ4] {
            expect_invalid_flags(sync.recv_v2("/f", flags).await, flags);
        }
        for flags in [
            SyncFlags::BROTLI | SyncFlags::LZ4,
            SyncFlags::BROTLI | SyncFlags::ZSTD,
            SyncFlags::LZ4 | SyncFlags::ZSTD,
            SyncFlags::BROTLI | SyncFlags::LZ4 | SyncFlags::ZSTD,
        ] {
            expect_invalid_flags(sync.recv_v2("/f", flags).await, flags);
            expect_invalid_flags(
                sync.send_v2("/f", FileMode(0o100644), 0, flags, b"x").await,
                flags,
            );
        }

        assert_eq!(sync.stat("/after").await.unwrap().size, 7);
        sync.quit().await.unwrap();
        rt::join(device).await;
    }
}
}

rt_test! {
async fn sync_path_with_a_nul_is_refused_before_anything_else() {
    // adbd would cut each of these at the NUL, in a request that looks
    // fine from here. The device with no features shows that the path
    // comes before the feature checks, and DRY_RUN on RCV2 that it comes
    // before the flags too.
    let mode = FileMode(0o100644);
    for banner in [device_with(&ALL_SYNC_FEATURES), FakeDevice::new()] {
        let (mut conn, device) =
            session(banner, b"host::features=", expect_only_a_stat_of_after).await;

        let mut buf = [0u8; 256];
        let mut sync = sync::open(&mut conn, &mut buf).await.unwrap();

        for path in ["/sdcard/a\0b", "/sdcard/a\0", "\0/sdcard/a"] {
            expect_invalid_path(sync.stat(path).await);
            expect_invalid_path(sync.stat_v2(path).await);
            expect_invalid_path(sync.list(path).await);
            expect_invalid_path(sync.list_v2(path).await);
            expect_invalid_path(sync.recv_start(path).await);
            expect_invalid_path(sync.recv_v2_start(path, SyncFlags::NONE).await);
            expect_invalid_path(sync.recv_v2_start(path, SyncFlags::DRY_RUN).await);
            expect_invalid_path(sync.send_start(path, mode).await);
            expect_invalid_path(sync.send_v2_start(path, mode, SyncFlags::NONE).await);
        }

        assert_eq!(sync.stat("/after").await.unwrap().size, 7);
        sync.quit().await.unwrap();
        rt::join(device).await;
    }
}
}
