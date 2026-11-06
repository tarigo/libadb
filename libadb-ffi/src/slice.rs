/// Build a `&[u8]` from a C caller's `(ptr, len)` pair. A null `ptr`
/// gives an empty slice; with a non-zero `len` it fails a debug
/// assertion, so callers refuse that pair first.
///
/// # Safety
///
/// If `ptr` is non-null, `ptr` and `len` must meet the requirements of
/// [`core::slice::from_raw_parts`] for the returned lifetime.
pub(crate) unsafe fn from_ptr<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    debug_assert!(!ptr.is_null() || len == 0, "null ptr with len={len}");
    if ptr.is_null() {
        &[]
    } else {
        // SAFETY: non-null branch, caller upholds the contract above.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

/// [`from_ptr`] for a `&mut [u8]`.
///
/// # Safety
///
/// If `ptr` is non-null, `ptr` and `len` must meet the requirements of
/// [`core::slice::from_raw_parts_mut`] for the returned lifetime.
pub(crate) unsafe fn from_mut_ptr<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    debug_assert!(!ptr.is_null() || len == 0, "null ptr with len={len}");
    if ptr.is_null() {
        &mut []
    } else {
        // SAFETY: non-null branch, caller upholds the contract above.
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
}

/// Copy `src` into `(buf, buf_len)`, truncating, and write the full
/// length through `out_len`, with the convention of
/// [`adb_connection_features`](crate::adb_connection_features).
///
/// # Safety
///
/// `buf` must be NULL or valid for writes of `buf_len` bytes, not
/// overlapping `src`; `out_len` must be NULL or valid for a write.
pub(crate) unsafe fn copy_out(src: &[u8], buf: *mut u8, buf_len: usize, out_len: *mut usize) {
    if !out_len.is_null() {
        // SAFETY: non-null, so writable per the contract above.
        unsafe { *out_len = src.len() };
    }
    if !buf.is_null() && buf_len > 0 {
        let n = src.len().min(buf_len);
        // SAFETY: non-null, so writable for `buf_len >= n` bytes per the contract above.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), buf, n) };
    }
}
