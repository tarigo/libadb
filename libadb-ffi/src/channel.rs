//! Channel traffic: opening a channel, reading, writing and closing it,
//! and the 64-bit id a C caller names it by.

use libadb::base::channel::ChannelId;

use crate::connection::adb_connection_t;
use crate::error::{self, AdbStatus};
use crate::slice;

pub(crate) fn encode_channel_id(ch: ChannelId) -> u64 {
    ((ch.local_id() as u64) << 32) | (ch.slot() as u32 as u64)
}

fn decode_channel_id(id: u64) -> ChannelId {
    ChannelId::from_raw((id & 0xFFFF_FFFF) as u32 as usize, (id >> 32) as u32)
}

/// Open a new channel to `destination`.
///
/// `destination` is an ADB service string, e.g. `"shell:ls"`,
/// `"tcp:8080"`, `"sync:"`. It does not need to be null-terminated.
/// On success, `*out_id` receives a 64-bit channel ID (packed slot +
/// wire local_id) usable with the other `adb_*_channel` functions
/// until it is closed. A channel ID from a closed channel is stale:
/// calls against it fail with [`AdbStatus::ChannelClosed`] even if
/// the slot has since been reused for a new channel.
///
/// # Safety
/// `conn` must be a valid handle. `destination` must be NULL or point
/// to at least `destination_len` readable bytes. `out_id` must point
/// to a writable `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_open_channel(
    conn: *mut adb_connection_t,
    destination: *const u8,
    destination_len: usize,
    out_id: *mut u64,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_id.is_null() || (destination.is_null() && destination_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    // SAFETY: readable for `destination_len` bytes when non-null, per `# Safety`.
    let dest = unsafe { slice::from_ptr(destination, destination_len) };
    let mut g = conn.lock_reader();
    let id = ffi_try!(g.open_channel(dest));
    // SAFETY: non-null, and writable per `# Safety`.
    unsafe { *out_id = encode_channel_id(id) };
    AdbStatus::Ok
}

/// Read from a channel into `buf` (up to `buf_len` bytes). Writes the
/// number of bytes actually read through `out_read`.
///
/// A return of `ADB_OK` with `*out_read == 0` never occurs; channel
/// closure is reported as [`AdbStatus::ChannelClosed`]. That is what
/// makes `while (adb_read_channel(...) == ADB_OK)` a correct loop, so
/// `buf_len == 0` is rejected with [`AdbStatus::InvalidArg`] rather
/// than answering with a zero that the loop would spin on, and a
/// zero-length WRTE from the device — legal, and delivering nothing —
/// is read past instead of surfacing as that same zero.
///
/// # Safety
/// `conn` must be a valid handle. `buf` must be NULL or point to at
/// least `buf_len` writable bytes. `out_read` must point to a
/// writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_read_channel(
    conn: *mut adb_connection_t,
    id: u64,
    buf: *mut u8,
    buf_len: usize,
    out_read: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_read.is_null() || (buf.is_null() && buf_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    if buf_len == 0 {
        return error::fail_invalid_arg("buf_len is zero");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    // SAFETY: non-null, as `buf_len` is not zero, and writable for it per `# Safety`.
    let slice = unsafe { slice::from_mut_ptr(buf, buf_len) };
    let mut g = conn.lock_reader();
    let ch = decode_channel_id(id);
    // The reader hands back Ok(0) for a zero-length WRTE; the C
    // contract above forbids returning it.
    let n = loop {
        let n = ffi_try!(g.read_channel(ch, slice));
        if n > 0 {
            break n;
        }
    };
    // SAFETY: non-null, and writable per `# Safety`.
    unsafe { *out_read = n };
    AdbStatus::Ok
}

/// Write `buf_len` bytes from `buf` to a channel. Returns only after
/// all bytes have been framed and handed to the transport (chunked to
/// the negotiated `max_payload` and flow-controlled).
///
/// Does not require the reader mutex — safe to call concurrently with
/// [`adb_read_channel`] on another thread.
///
/// # Safety
/// `conn` must be a valid handle. `buf` must be NULL or point to at
/// least `buf_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_write_channel(
    conn: *mut adb_connection_t,
    id: u64,
    buf: *const u8,
    buf_len: usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || (buf.is_null() && buf_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    // SAFETY: readable for `buf_len` bytes when non-null, per `# Safety`.
    let slice = unsafe { slice::from_ptr(buf, buf_len) };
    let ch = decode_channel_id(id);
    ffi_try!(conn.writer.write_channel(ch, slice));
    AdbStatus::Ok
}

/// Close a channel. Subsequent reads/writes against this ID will fail
/// with [`AdbStatus::ChannelClosed`].
///
/// # Safety
/// `conn` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_close_channel(conn: *mut adb_connection_t, id: u64) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    let ch = decode_channel_id(id);
    ffi_try!(conn.writer.close_channel(ch));
    AdbStatus::Ok
}
