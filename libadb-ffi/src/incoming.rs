//! Channels the device opens toward the host: waiting for one, then
//! accepting or rejecting it.

use crate::channel::encode_channel_id;
use crate::connection::{adb_connection_t, lock_poisoned};
use crate::error::{self, AdbStatus};
use crate::slice::copy_out;

/// Report the staged device-initiated channel (`adb reverse` traffic),
/// waiting for one to arrive if none is staged, and copy its
/// destination into `(dest, dest_cap, out_dest_len)` per
/// [`adb_connection_features`]. The request stays staged on the handle
/// until [`adb_incoming_accept`] or [`adb_incoming_reject`] consumes
/// exactly it — repeated calls report the same request again, which is
/// what makes the truncate-and-report convention usable here: probe
/// with `(NULL, 0, &len)`, allocate, call again for the bytes.
///
/// [`adb_connection_features`]: crate::adb_connection_features
///
/// With nothing staged this blocks until a channel arrives, exactly as
/// [`adb_read_channel`] blocks for data, and — like it — holds the read
/// lock while waiting, so a device that never opens one parks this
/// call. The staged request is held locked for the whole call, so
/// concurrent reports and verdicts serialize against it rather than
/// racing for the queue. There is no way to interrupt it yet; in
/// particular the handle must stay alive until this returns — freeing
/// it from another thread while a call is blocked is undefined
/// behaviour, not an interruption mechanism.
///
/// [`adb_read_channel`]: crate::adb_read_channel
///
/// # Safety
/// `conn` must be a valid handle and must not be freed while this call
/// is in flight. `dest` must be NULL or writable for `dest_cap` bytes;
/// `out_dest_len` must be NULL or a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_accept_channel(
    conn: *mut adb_connection_t,
    dest: *mut u8,
    dest_cap: usize,
    out_dest_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    // The staged lock is held across the empty check, the dequeue and
    // the store: concurrent reports serialize on one staged request —
    // a re-report of the same holder, never two racing holders. The
    // reader lock nests inside it, in that order only.
    let mut staged = lock_poisoned(&conn.staged_incoming);
    // A request already staged is re-reported, not displaced — that
    // keeps probe-allocate-copy sequences working on one request.
    if let Some(incoming) = staged.as_ref() {
        // SAFETY: `dest` and `out_dest_len` are NULL or writable as sized, per `# Safety`.
        unsafe { copy_out(incoming.destination(), dest, dest_cap, out_dest_len) };
        return AdbStatus::Ok;
    }
    let mut g = conn.lock_reader();
    let incoming = ffi_try!(g.accept_incoming());
    drop(g);
    // SAFETY: `dest` and `out_dest_len` are NULL or writable as sized, per `# Safety`.
    unsafe { copy_out(incoming.destination(), dest, dest_cap, out_dest_len) };
    // Stage the request itself: the verdict calls consume it, so they
    // cannot answer some other OPEN that queued up in the meantime.
    *staged = Some(incoming);
    AdbStatus::Ok
}

/// Accept the channel staged by [`adb_accept_channel`], returning its
/// ID through `out_id`.
///
/// # Safety
/// `conn` must be a valid handle; `out_id` a writable `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_incoming_accept(
    conn: *mut adb_connection_t,
    out_id: *mut u64,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_id.is_null() {
        return error::fail_invalid_arg("null pointer");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let conn = unsafe { &*conn };
    let staged = lock_poisoned(&conn.staged_incoming).take();
    let Some(incoming) = staged else {
        return error::fail_invalid_arg("no incoming channel is staged");
    };
    let ch = ffi_try!(incoming.accept());
    // SAFETY: non-null, and writable per `# Safety`.
    unsafe { *out_id = encode_channel_id(ch) };
    AdbStatus::Ok
}

/// Reject the channel staged by [`adb_accept_channel`].
///
/// # Safety
/// `conn` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_incoming_reject(conn: *mut adb_connection_t) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    // SAFETY: non-null, and a valid handle per `# Safety`.
    let staged = lock_poisoned(&unsafe { &*conn }.staged_incoming).take();
    let Some(incoming) = staged else {
        return error::fail_invalid_arg("no incoming channel is staged");
    };
    ffi_try!(incoming.reject());
    AdbStatus::Ok
}
