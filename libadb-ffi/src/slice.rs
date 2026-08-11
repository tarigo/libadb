/// Build a `&[u8]` from a C caller's `(ptr, len)` pair. `ptr == null`
/// with any `len` is treated as empty.
///
/// # Safety
///
/// If `ptr` is non-null, the caller must guarantee the invariants of
/// [`core::slice::from_raw_parts`]: `ptr` is valid for reads of
/// `len * size_of::<u8>()` bytes and properly aligned, the memory is
/// not mutated for the returned lifetime, and `len` fits in `isize`.
pub(crate) unsafe fn from_ptr<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    debug_assert!(!ptr.is_null() || len == 0, "null ptr with len={len}");
    if ptr.is_null() {
        &[]
    } else {
        // SAFETY: non-null branch, caller upholds the contract above.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

/// Build a `&mut [u8]` from a C caller's `(ptr, len)` pair. `ptr == null`
/// with any `len` is treated as empty.
///
/// # Safety
///
/// If `ptr` is non-null, the caller must guarantee the invariants of
/// [`core::slice::from_raw_parts_mut`]: `ptr` is valid for reads and
/// writes of `len * size_of::<u8>()` bytes, properly aligned, no other
/// reference aliases the region for the returned lifetime, and `len`
/// fits in `isize`.
pub(crate) unsafe fn from_mut_ptr<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    debug_assert!(!ptr.is_null() || len == 0, "null ptr with len={len}");
    if ptr.is_null() {
        &mut []
    } else {
        // SAFETY: non-null branch, caller upholds the contract above.
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
}
