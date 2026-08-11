macro_rules! ffi_try {
    ($expr:expr) => {
        match $crate::block_on::block_on($expr) {
            Ok(v) => v,
            Err(e) => return $crate::error::fail_error(e),
        }
    };
}
