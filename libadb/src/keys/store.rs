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

use super::{AdbKey, KeyError, KeyName};

const PRIVATE_KEY_FILE: &str = "adbkey";
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
    /// so nothing on disk needs fixing.
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
    name: KeyName<'_>,
) -> Result<AdbKey, StoreError> {
    let path = dir.join(PRIVATE_KEY_FILE);
    let bytes = Zeroizing::new(fs::read(&path).map_err(|source| StoreError::Io {
        path: path.clone(),
        source,
    })?);
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
    name: KeyName<'_>,
) -> Result<AdbKey, StoreError> {
    let path = dir.join(PRIVATE_KEY_FILE);
    match File::open(&path) {
        Ok(_) => adopt(dir, rng, name),
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate_into(dir, rng, name),
        Err(source) => Err(StoreError::Io { path, source }),
    }
}

fn parse<R: CryptoRngCore + ?Sized>(
    pem: &str,
    rng: &mut R,
    name: KeyName<'_>,
) -> Result<AdbKey, KeyError> {
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        AdbKey::from_pkcs1_pem(pem, rng, name)
    } else {
        AdbKey::from_pkcs8_pem(pem, rng, name)
    }
}

fn generate_into<R: CryptoRngCore + ?Sized>(
    dir: &Path,
    rng: &mut R,
    name: KeyName<'_>,
) -> Result<AdbKey, StoreError> {
    create_dir(dir)?;
    let key = AdbKey::generate(rng, name).map_err(StoreError::Key)?;
    let pem = key.to_pkcs8_pem().map_err(StoreError::Key)?;

    if !publish_new(&dir.join(PRIVATE_KEY_FILE), pem.as_bytes())? {
        return adopt(dir, rng, name);
    }
    write_public_key(&dir.join(PUBLIC_KEY_FILE), &key)?;
    Ok(key)
}

fn write_public_key(path: &Path, key: &AdbKey) -> Result<(), StoreError> {
    install(path, key.public_key_line(), false)
}

fn adopt<R: CryptoRngCore + ?Sized>(
    dir: &Path,
    rng: &mut R,
    name: KeyName<'_>,
) -> Result<AdbKey, StoreError> {
    let key = load(dir, rng, name)?;
    ensure_public_key(dir, &key)?;
    Ok(key)
}

fn ensure_public_key(dir: &Path, key: &AdbKey) -> Result<(), StoreError> {
    let public = dir.join(PUBLIC_KEY_FILE);
    if public.exists() {
        return Ok(());
    }
    write_public_key(&public, key)
}

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

fn create_dir(dir: &Path) -> Result<(), StoreError> {
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
