//! ADB `shell:` service — two wire protocol versions under one family.
//!
//! * [`v1`] — legacy `shell:` wire destination. Interleaved stdout/stderr
//!   on the same byte stream, no exit code, no PTY signaling.
//! * [`v2`] — modern `shell,v2,…:` wire destination. Framed
//!   stdout/stderr/exit and optional PTY controls.
//!
//! Both submodules expose a `Shell` type (and matching `open`/`exec`
//! free functions). Use `v2` when the device advertises
//! [`Feature::ShellV2`](crate::Feature::ShellV2); fall back to `v1`
//! otherwise, or use [`crate::cmd`] for automatic selection.

pub mod v1;
pub mod v2;
