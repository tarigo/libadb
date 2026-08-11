#![allow(clippy::await_holding_lock)]

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use libadb::base::channel::ChannelId;
use libadb::base::error::{Error, ProtocolError};
use libadb::shell::v2::{FrameDecoder, CLOSE_STDIN, STDIN, WINDOW_SIZE_CHANGE};

use crate::block_on;
use crate::error::{self, AdbStatus};
use crate::transport::FfiTransportError;
use crate::{lock_poisoned, FfiReader, FfiWriter};

fn build_shell_v2_destination(
    pty: bool,
    term: &str,
    command: &str,
) -> Result<String, ProtocolError> {
    if command.contains('\0') || term.contains('\0') {
        return Err(ProtocolError::InvalidDestination);
    }
    Ok(match (pty, term.is_empty()) {
        (false, _) => format!("shell,v2,raw:{command}\0"),
        (true, true) => format!("shell,v2,pty:{command}\0"),
        (true, false) => format!("shell,v2,pty,TERM={term}:{command}\0"),
    })
}

fn encode_window_size(rows: u16, cols: u16) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&rows.to_le_bytes());
    buf[2..4].copy_from_slice(&cols.to_le_bytes());
    buf
}

const SHELL_V2_RX_BUF: usize = 64 * 1024;

struct ParseState {
    rx: Vec<u8>,
    decoder: FrameDecoder,
}

impl ParseState {
    fn new() -> Self {
        Self {
            rx: vec![0u8; SHELL_V2_RX_BUF],
            decoder: FrameDecoder::new(),
        }
    }

    fn try_next_frame(&mut self) -> Result<Option<(u8, Vec<u8>)>, Error<FfiTransportError>> {
        self.decoder.try_next_raw(&self.rx).map_err(Error::Protocol)
    }

    fn ensure_writable(&mut self) -> Result<(), Error<FfiTransportError>> {
        if self.decoder.tail() < self.rx.len() {
            return Ok(());
        }
        self.decoder.compact(&mut self.rx);
        if self.decoder.tail() == self.rx.len() {
            return Err(Error::ReceiveBufferFull);
        }
        Ok(())
    }
}

/// Opaque shell_v2 session handle.
///
/// No outer mutex: each field guards its own mutable state, so reader
/// and writer paths can run concurrently without contending on a single
/// session-wide lock.
#[allow(non_camel_case_types)]
pub struct adb_shell_t {
    reader: Arc<Mutex<FfiReader>>,
    writer: FfiWriter,
    channel_id: ChannelId,
    parse_state: Mutex<ParseState>,
    closed: AtomicBool,
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<adb_shell_t>();
};

async fn read_frame_async(
    reader_arc: &Mutex<FfiReader>,
    parse_state: &Mutex<ParseState>,
    channel_id: ChannelId,
) -> Result<(u8, Vec<u8>), Error<FfiTransportError>> {
    let mut p = lock_poisoned(parse_state);
    loop {
        if let Some(frame) = p.try_next_frame()? {
            return Ok(frame);
        }
        p.ensure_writable()?;
        let tail = p.decoder.tail();
        let n = {
            let dst = &mut p.rx[tail..];
            let mut r = lock_poisoned(reader_arc);
            r.read_channel(channel_id, dst).await?
        };
        p.decoder.commit(n);
    }
}

async fn send_frame_async(
    writer: &FfiWriter,
    channel_id: ChannelId,
    id: u8,
    payload: &[u8],
) -> Result<(), Error<FfiTransportError>> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol(ProtocolError::PayloadTooLarge))?;
    let b = len.to_le_bytes();
    let hdr = [id, b[0], b[1], b[2], b[3]];
    writer.write_channel(channel_id, &hdr).await?;
    if !payload.is_empty() {
        writer.write_channel(channel_id, payload).await?;
    }
    Ok(())
}

/// Open a shell_v2 session.
///
/// * `command` — shell command (need not be null-terminated; must be UTF-8).
///   Pass empty to start a login shell (only meaningful with `pty == true`).
/// * `pty`     — if true, opens `shell,v2,pty,...:`; otherwise `shell,v2,raw:`.
/// * `term`    — value for the device's `TERM` env var (e.g. `"xterm-256color"`).
///   Null or empty omits it. Ignored when `pty` is false.
/// * `rows`, `cols` — if `pty` and either is non-zero, a `WINDOW_SIZE_CHANGE`
///   frame is sent right after the channel opens.
///
/// On success, `*out_sh` receives a handle that must be released with
/// [`adb_shell_free`]. Call [`adb_shell_close`] beforehand to tear down the
/// channel gracefully.
///
/// # Safety
/// `conn` must be a valid handle and must outlive the returned session.
/// Pointers must be valid for the indicated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_open(
    conn: *mut super::adb_connection_t,
    command: *const u8,
    command_len: usize,
    pty: bool,
    term: *const c_char,
    rows: u16,
    cols: u16,
    out_sh: *mut *mut adb_shell_t,
) -> AdbStatus {
    error::clear_last_error();
    if conn.is_null() || out_sh.is_null() || (command.is_null() && command_len > 0) {
        return error::fail_invalid_arg("null pointer");
    }

    let cmd_bytes = super::slice::from_ptr(command, command_len);
    let cmd_str = match core::str::from_utf8(cmd_bytes) {
        Ok(s) => s,
        Err(e) => return error::fail_invalid_arg(e),
    };
    let term_str = if term.is_null() {
        ""
    } else {
        match CStr::from_ptr(term).to_str() {
            Ok(s) => s,
            Err(e) => return error::fail_invalid_arg(e),
        }
    };

    let dest = match build_shell_v2_destination(pty, term_str, cmd_str) {
        Ok(d) => d,
        Err(e) => return error::fail_error::<FfiTransportError>(Error::Protocol(e)),
    };

    let reader_arc = Arc::clone(&(*conn).reader);
    let writer = (*conn).writer.clone();

    let channel_id = {
        let mut r = lock_poisoned(&reader_arc);
        ffi_try!(r.open_channel(dest.as_bytes()))
    };

    if pty && (rows != 0 || cols != 0) {
        let payload = encode_window_size(rows, cols);
        let res = block_on::block_on(send_frame_async(
            &writer,
            channel_id,
            WINDOW_SIZE_CHANGE,
            &payload,
        ));
        if let Err(e) = res {
            let _ = block_on::block_on(writer.close_channel(channel_id));
            return error::fail_error(e);
        }
    }

    let boxed = Box::new(adb_shell_t {
        reader: reader_arc,
        writer,
        channel_id,
        parse_state: Mutex::new(ParseState::new()),
        closed: AtomicBool::new(false),
    });
    *out_sh = Box::into_raw(boxed);
    AdbStatus::Ok
}

/// Release a handle previously returned by [`adb_shell_open`].
///
/// NULL is a no-op. The channel is not closed automatically — call
/// [`adb_shell_close`] first to avoid leaking the channel on the device.
///
/// # Safety
/// `sh` must be NULL or a handle returned by [`adb_shell_open`] that has
/// not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_free(sh: *mut adb_shell_t) {
    if sh.is_null() {
        return;
    }
    drop(Box::from_raw(sh));
}

/// Read one decoded shell_v2 frame.
///
/// `*out_id` receives the frame id (see `ADB_SHELL_V2_*` constants).
/// Up to `buf_cap` bytes of payload are copied into `buf`; `*out_len`
/// receives the full payload length (a value greater than `buf_cap`
/// means truncation — the overflow is discarded).
///
/// Large frames whose payload exceeds the internal rx buffer are
/// delivered in multiple consecutive calls with the same id — concatenate
/// the chunks to reconstruct the payload.
///
/// Channel closure is reported as [`AdbStatus::ChannelClosed`].
///
/// # Safety
/// `sh` must be a valid handle. `out_id` must point to a writable `u8`.
/// `buf` must be NULL or point to at least `buf_cap` writable bytes.
/// `out_len` may be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_read_frame(
    sh: *mut adb_shell_t,
    out_id: *mut u8,
    buf: *mut u8,
    buf_cap: usize,
    out_len: *mut usize,
) -> AdbStatus {
    error::clear_last_error();
    if sh.is_null() || out_id.is_null() || (buf.is_null() && buf_cap > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    if (*sh).closed.load(Ordering::Acquire) {
        return AdbStatus::ChannelClosed;
    }
    let (id, payload) = ffi_try!(read_frame_async(
        &(*sh).reader,
        &(*sh).parse_state,
        (*sh).channel_id,
    ));
    *out_id = id;
    if !out_len.is_null() {
        *out_len = payload.len();
    }
    if !buf.is_null() && buf_cap > 0 {
        let n = payload.len().min(buf_cap);
        ptr::copy_nonoverlapping(payload.as_ptr(), buf, n);
    }
    AdbStatus::Ok
}

/// Send a `STDIN` frame.
///
/// # Safety
/// `sh` must be a valid handle. `data` must be NULL or point to at least
/// `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_write_stdin(
    sh: *mut adb_shell_t,
    data: *const u8,
    len: usize,
) -> AdbStatus {
    error::clear_last_error();
    if sh.is_null() || (data.is_null() && len > 0) {
        return error::fail_invalid_arg("null pointer");
    }
    let payload = super::slice::from_ptr(data, len);
    send_frame_payload(sh, STDIN, payload)
}

/// Send a `CLOSE_STDIN` frame — no more stdin will follow.
///
/// # Safety
/// `sh` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_close_stdin(sh: *mut adb_shell_t) -> AdbStatus {
    error::clear_last_error();
    if sh.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    send_frame_payload(sh, CLOSE_STDIN, &[])
}

/// Send a `WINDOW_SIZE_CHANGE` frame.
///
/// # Safety
/// `sh` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_set_window_size(
    sh: *mut adb_shell_t,
    rows: u16,
    cols: u16,
) -> AdbStatus {
    error::clear_last_error();
    if sh.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    let payload = encode_window_size(rows, cols);
    send_frame_payload(sh, WINDOW_SIZE_CHANGE, &payload)
}

/// Close the underlying channel. Subsequent read/write ops on this
/// handle return [`AdbStatus::ChannelClosed`]. Idempotent.
///
/// # Safety
/// `sh` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adb_shell_close(sh: *mut adb_shell_t) -> AdbStatus {
    error::clear_last_error();
    if sh.is_null() {
        return error::fail_invalid_arg("null handle");
    }
    if (*sh)
        .closed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return AdbStatus::Ok;
    }
    let ch = (*sh).channel_id;
    ffi_try!((*sh).writer.close_channel(ch));
    AdbStatus::Ok
}

unsafe fn send_frame_payload(sh: *mut adb_shell_t, id: u8, payload: &[u8]) -> AdbStatus {
    if (*sh).closed.load(Ordering::Acquire) {
        return AdbStatus::ChannelClosed;
    }
    let ch = (*sh).channel_id;
    ffi_try!(send_frame_async(&(*sh).writer, ch, id, payload));
    AdbStatus::Ok
}
