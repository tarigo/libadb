//! Shared key setup for the examples: reuse `~/.android/adbkey`, or
//! generate and save one on first run.
//!
//! The library takes the key directory as a parameter and reads no
//! environment of its own; resolving `~/.android` is this caller's job,
//! as it would be in any application.
//!
//! Included by each binary example via `#[path]`:
//!
//! ```ignore
//! #[path = "common/adb_key_auth.rs"]
//! mod adb_key_auth;
//! ```

use std::path::PathBuf;
use std::{env, error, fs};

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::{store, AdbKey};

/// Load the key the standard adb client uses, generating one if the
/// user has never run `adb` — the device asks to confirm it once.
pub fn load_or_generate() -> Result<AdbKey, Box<dyn error::Error>> {
    let home = env::var("HOME").map_err(|_| "HOME is not set; cannot locate ~/.android")?;
    let dir = PathBuf::from(home).join(".android");
    let key = store::load_or_generate(&dir, &mut OsRng, &name())?;
    Ok(key)
}

/// The `user@host` comment shown in the device's authorization dialog.
fn name() -> String {
    let user = env::var("USER").unwrap_or_else(|_| String::from("libadb"));
    let host = fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| String::from("host"));
    format!("{user}@{host}")
}
