//! Nothing lives here: the whole crate is its build script and the
//! `tests/header.rs` conformance test, which compare the hand-written
//! `libadb-ffi/include/libadb.h` against the Rust implementation.
//! Run it with `just ffi-header`.

#![no_std]
