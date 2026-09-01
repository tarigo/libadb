//! Host key store: the `adbkey` / `adbkey.pub` pair on disk.
//!
//! The files are the ones the official client uses, in the same
//! formats, so pointing this at `~/.android` reuses the identity a
//! device has already been asked to trust — no second confirmation
//! dialog, and no `adb` installation. The directory is always a
//! parameter: the library reads no environment and picks no path of
//! its own.

use alloc::format;
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rsa::rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use super::{AdbKey, KeyError};

/// Private key file, as named by `adb keygen`.
const PRIVATE_KEY_FILE: &str = "adbkey";
/// Public key file: a convenience artifact for other tools, never read.
const PUBLIC_KEY_FILE: &str = "adbkey.pub";

/// Errors from reading or writing a key directory.
#[derive(Debug)]
pub enum StoreError {
    /// Reading or writing `path` failed.
    Io {
        /// The file involved.
        path: PathBuf,
        /// What the filesystem said.
        source: io::Error,
    },
    /// `path` exists but holds no key we can parse. It is left exactly
    /// as it was — an identity a device may already trust is never
    /// overwritten — so repair or remove it by hand.
    Malformed {
        /// The file involved.
        path: PathBuf,
        /// Why it would not parse.
        source: KeyError,
    },
    /// `path` holds bytes that are not even text, so it is not a key
    /// file at all. Left untouched, like any key that will not parse:
    /// a caller asking "is the file at fault?" matches this and
    /// [`Malformed`](Self::Malformed) alike.
    NotAKeyFile {
        /// The file involved.
        path: PathBuf,
    },
    /// Making or encoding the key failed. Nothing on disk is at fault,
    /// so nothing on disk needs fixing — the name or the generator
    /// does.
    Key(KeyError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => f.write_fmt(format_args!("{}: {source}", path.display())),
            Self::Malformed { path, source } => f.write_fmt(format_args!(
                "{}: not a usable key ({source}); left untouched, remove it to start over",
                path.display()
            )),
            Self::NotAKeyFile { path } => f.write_fmt(format_args!(
                "{}: not text, so not a key file; left untouched, remove it to start over",
                path.display()
            )),
            Self::Key(source) => f.write_fmt(format_args!("could not make a key: {source}")),
        }
    }
}

impl core::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Malformed { source, .. } => Some(source),
            Self::NotAKeyFile { .. } => None,
            Self::Key(source) => Some(source),
        }
    }
}

/// Load `dir/adbkey`, accepting either PKCS#8 or the PKCS#1 that older
/// adb releases wrote.
///
/// The public key is derived from the private one, so `adbkey.pub` is
/// never read: it can be absent, stale or someone else's.
pub fn load<R: CryptoRngCore + ?Sized>(
    dir: &Path,
    rng: &mut R,
    name: &str,
) -> Result<AdbKey, StoreError> {
    // A name the format cannot carry is the caller's mistake, not the
    // file's: check it before any file is blamed for it.
    crate::keys::pubkey::validate_name(name).map_err(StoreError::Key)?;

    let path = dir.join(PRIVATE_KEY_FILE);
    // The file is the private key in the clear; the buffer goes the
    // same way as everything else that has held it.
    let bytes = Zeroizing::new(fs::read(&path).map_err(|source| StoreError::Io {
        path: path.clone(),
        source,
    })?);
    // Reading as text would report a binary file as an IO fault, when
    // the fault is the file's.
    let pem =
        core::str::from_utf8(&bytes).map_err(|_| StoreError::NotAKeyFile { path: path.clone() })?;
    parse(pem, rng, name).map_err(|source| StoreError::Malformed { path, source })
}

/// [`load`] the key in `dir`, or generate one and persist it there.
///
/// A first run writes `adbkey` (owner-only) and `adbkey.pub`, creating
/// `dir` if needed, and the device asks the user to confirm the new key
/// once. An existing key is reused untouched; an existing key that will
/// not parse is an error, never a reason to overwrite. Only the missing
/// `adbkey.pub` beside a good key is rewritten.
///
/// `rng` is not only for generating: a loaded key seeds its own
/// blinding generator from it, which is why reading a key needs
/// entropy too.
///
/// Two processes racing on an empty directory both generate, and the
/// first to publish wins; the other adopts that key rather than its
/// own, since it is the one the device may have been asked to trust.
pub fn load_or_generate<R: CryptoRngCore + ?Sized>(
    dir: &Path,
    rng: &mut R,
    name: &str,
) -> Result<AdbKey, StoreError> {
    crate::keys::pubkey::validate_name(name).map_err(StoreError::Key)?;

    let path = dir.join(PRIVATE_KEY_FILE);
    // Opened, not read: whether the contents parse is `load`'s to say,
    // only "nothing here" may lead to generating, and a probe has no
    // business lifting the key into memory.
    match File::open(&path) {
        Ok(_) => adopt(dir, rng, name),
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate_into(dir, rng, name),
        Err(source) => Err(StoreError::Io { path, source }),
    }
}

fn parse<R: CryptoRngCore + ?Sized>(
    pem: &str,
    rng: &mut R,
    name: &str,
) -> Result<AdbKey, KeyError> {
    // adb wrote PKCS#1 for years, and such a key is exactly the
    // identity worth reusing.
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        AdbKey::from_pkcs1_pem(pem, rng, name)
    } else {
        AdbKey::from_pkcs8_pem(pem, rng, name)
    }
}

fn generate_into<R: CryptoRngCore + ?Sized>(
    dir: &Path,
    rng: &mut R,
    name: &str,
) -> Result<AdbKey, StoreError> {
    create_dir(dir)?;
    let key = AdbKey::generate(rng, name).map_err(StoreError::Key)?;
    let pem = key.to_pkcs8_pem().map_err(StoreError::Key)?;

    // Generation takes long enough for `adb` itself to have created a
    // key meanwhile, and that one may already be trusted: publishing
    // without clobbering lets the first writer win, and the loser
    // adopts the winner rather than replacing it.
    if !publish_new(&dir.join(PRIVATE_KEY_FILE), pem.as_bytes())? {
        // The winner may have died between publishing its key and
        // writing the derived file, so the promise to leave both
        // behind falls to whoever is still here.
        return adopt(dir, rng, name);
    }
    write_public_key(&dir.join(PUBLIC_KEY_FILE), &key)?;
    Ok(key)
}

fn write_public_key(path: &Path, key: &AdbKey) -> Result<(), StoreError> {
    install(path, key.public_key_line(), false)
}

/// Take the key that is already on disk, deriving its public file if
/// whoever put it there did not get that far.
fn adopt<R: CryptoRngCore + ?Sized>(
    dir: &Path,
    rng: &mut R,
    name: &str,
) -> Result<AdbKey, StoreError> {
    let key = load(dir, rng, name)?;
    ensure_public_key(dir, &key)?;
    Ok(key)
}

/// Write the derived public file if it is not there. It is the same
/// bytes for anyone holding this key, so rewriting it costs nothing
/// and leaving it missing costs the tools that look for it.
fn ensure_public_key(dir: &Path, key: &AdbKey) -> Result<(), StoreError> {
    let public = dir.join(PUBLIC_KEY_FILE);
    if public.exists() {
        return Ok(());
    }
    write_public_key(&public, key)
}

/// Put `bytes` at `path` only if nothing is there yet, reporting
/// whether this call is the one that installed them.
///
/// `rename` would overwrite, which is the one thing the store must not
/// do to a key: linking fails instead, and the caller adopts whatever
/// won.
fn publish_new(path: &Path, bytes: &[u8]) -> Result<bool, StoreError> {
    let tmp = write_temp(path, bytes, true)?;
    let installed = match fs::hard_link(&tmp, path) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(source) => {
            let _ = fs::remove_file(&tmp);
            return Err(StoreError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let _ = fs::remove_file(&tmp);
    Ok(installed)
}

/// Put `bytes` at `path`, replacing what is there. For the public
/// file, which is derived and may be rewritten freely.
fn install(path: &Path, bytes: &[u8], private: bool) -> Result<(), StoreError> {
    let tmp = write_temp(path, bytes, private)?;
    fs::rename(&tmp, path).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        StoreError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Write `bytes` to a fresh file beside `path` and return its name, so
/// a reader never meets a half-written key.
///
/// The name is unique per call, not per process: two threads writing
/// the same key file would otherwise share one temporary and one of
/// them would go on writing into the file the other had already
/// published.
fn write_temp(path: &Path, bytes: &[u8], private: bool) -> Result<PathBuf, StoreError> {
    static NEXT: AtomicU32 = AtomicU32::new(0);

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let pid = std::process::id();

    let mut last = None;
    for _ in 0..16 {
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_file_name(format!(".{name}.{pid}.{seq}.tmp"));
        match create(&tmp, private).and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        }) {
            Ok(()) => return Ok(tmp),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(source) => {
                let _ = fs::remove_file(&tmp);
                return Err(StoreError::Io { path: tmp, source });
            }
        }
    }
    Err(StoreError::Io {
        path: path.to_path_buf(),
        source: last.unwrap_or_else(|| io::Error::other("no free temporary name")),
    })
}

/// Create a file that must not exist yet. On Windows there are no mode
/// bits and it inherits the profile's ACL, which is what `adb keygen`
/// relies on there too; elsewhere the private half is owner-only.
fn create(path: &Path, private: bool) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode_for(private));
    }

    let file = options.open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` above is filtered by the umask, which may leave the
        // owner without write on a hostile one.
        file.set_permissions(fs::Permissions::from_mode(mode_for(private)))?;
    }
    Ok(file)
}

#[cfg(unix)]
fn mode_for(private: bool) -> u32 {
    if private {
        0o600
    } else {
        0o644
    }
}

/// Create the key directory and every parent it needs, closed to
/// others where the platform has mode bits — `0o750`, the mode adb
/// gives its own directory, so the owning group keeps the read and
/// traverse bits it has there.
fn create_dir(dir: &Path) -> Result<(), StoreError> {
    // One component at a time, each usable before we descend into it:
    // `mkdir` takes its mode through the umask, which is free to strip
    // the owner's own bits and leave a directory its owner cannot
    // enter — and `create_dir_all` would then fail halfway down.
    let mut path = PathBuf::new();
    for component in dir.components() {
        path.push(component);
        match create_one(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(StoreError::Io { path, source }),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_one(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fs::DirBuilder::new().mode(0o750).create(path)?;

    // Group and other keep whatever the umask allowed them; the owner
    // gets back what it takes to use the directory at all.
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o700 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_one(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_write_gets_a_temporary_of_its_own() {
        // Two threads writing the same key file would otherwise share
        // one temporary, and the loser would go on writing into the
        // file the winner had already published.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PRIVATE_KEY_FILE);

        let first = write_temp(&path, b"one", true).unwrap();
        let second = write_temp(&path, b"two", true).unwrap();

        assert_ne!(first, second);
        assert_eq!(fs::read(&first).unwrap(), b"one");
        assert_eq!(fs::read(&second).unwrap(), b"two");
    }
}
