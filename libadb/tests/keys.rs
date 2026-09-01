#![cfg(feature = "host-keys")]

//! What the host key store promises about a directory of key files.
//!
//! The point of the store is that a device which already trusts the
//! standard adb client keeps trusting us: we read its `adbkey` rather
//! than making a second identity. The other half of the promise is
//! negative — the store may create key files, but it must never
//! destroy one it cannot read.

use std::fs;
use std::io::ErrorKind;

use libadb::keys::rsa::rand_core::OsRng;
use libadb::keys::store::{self, StoreError};

#[path = "test_key/test_key.rs"]
mod test_key;
use test_key::{NAME, PKCS1_PEM, PKCS8_PEM};

/// The store writes what `adb keygen` writes, under the same names.
const PRIVATE: &str = "adbkey";
const PUBLIC: &str = "adbkey.pub";

// ---------------------------------------------------------------------------
// Tests: loading a key someone else made
// ---------------------------------------------------------------------------

#[test]
fn load_parses_an_existing_pkcs8_adbkey_and_derives_the_public_key() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), PKCS8_PEM).unwrap();

    let key = store::load(dir.path(), &mut OsRng, NAME).unwrap();

    assert!(
        key.public_key_wire().ends_with(b" unit@test\0"),
        "the public half must carry the name we were given"
    );
    assert!(
        !dir.path().join(PUBLIC).exists(),
        "adbkey.pub is a convenience artifact; the key comes from the private half alone"
    );
}

#[test]
fn load_accepts_a_legacy_pkcs1_adbkey() {
    let pkcs8_dir = tempfile::tempdir().unwrap();
    fs::write(pkcs8_dir.path().join(PRIVATE), PKCS8_PEM).unwrap();
    let expected = store::load(pkcs8_dir.path(), &mut OsRng, NAME).unwrap();

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), PKCS1_PEM).unwrap();

    let key = store::load(dir.path(), &mut OsRng, NAME).unwrap();

    assert_eq!(
        key.public_key_wire(),
        expected.public_key_wire(),
        "older adb releases wrote PKCS#1; the same key must load the same way"
    );
}

#[test]
fn load_reports_a_missing_adbkey_as_io_not_found() {
    let dir = tempfile::tempdir().unwrap();

    let err = store::load(dir.path(), &mut OsRng, NAME).unwrap_err();

    assert!(
        matches!(&err, StoreError::Io { source, .. } if source.kind() == ErrorKind::NotFound),
        "expected a NotFound Io error, got {err:?}"
    );
}

#[test]
fn a_store_error_says_which_file_it_is_about_and_keeps_the_cause() {
    use std::error::Error as _;

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), b"this is not a key").unwrap();

    let malformed = store::load(dir.path(), &mut OsRng, NAME).unwrap_err();
    let missing = store::load(tempfile::tempdir().unwrap().path(), &mut OsRng, NAME).unwrap_err();

    let shown = malformed.to_string();
    assert!(shown.contains("adbkey"), "the file is named: {shown}");
    assert!(
        shown.contains("left untouched"),
        "and the refusal to overwrite it is spelled out: {shown}"
    );
    assert!(
        malformed.source().is_some(),
        "the parse failure stays reachable for a caller that logs causes"
    );

    let shown = missing.to_string();
    assert!(
        shown.contains("adbkey"),
        "the file is named here too: {shown}"
    );
    assert!(missing.source().is_some(), "as does the io error");
}

#[test]
fn a_name_the_format_rejects_is_not_reported_as_a_broken_file() {
    // Nothing on disk is at fault here, so nothing on disk should be
    // blamed — least of all with advice to delete it.
    let dir = tempfile::tempdir().unwrap();

    let generating = store::load_or_generate(dir.path(), &mut OsRng, "unit@test\n").unwrap_err();

    // And with a perfectly good key already on disk, where blaming the
    // file would be worse still: deleting it cannot fix the name.
    fs::write(dir.path().join(PRIVATE), PKCS8_PEM).unwrap();
    let loading = store::load(dir.path(), &mut OsRng, "unit@test\n").unwrap_err();
    let reusing = store::load_or_generate(dir.path(), &mut OsRng, "unit@test\n").unwrap_err();

    for err in [&generating, &loading, &reusing] {
        assert!(
            matches!(err, StoreError::Key(_)),
            "expected Key, got {err:?}"
        );
        assert!(
            !err.to_string().contains("remove it"),
            "the message must not send the user after a file: {err}"
        );
    }
    assert_eq!(
        fs::read_to_string(dir.path().join(PRIVATE)).unwrap(),
        PKCS8_PEM,
        "and the key is still there"
    );
}

#[test]
fn a_corrupt_adbkey_fails_to_load_as_malformed() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), b"this is not a key").unwrap();

    let err = store::load(dir.path(), &mut OsRng, NAME).unwrap_err();

    assert!(
        matches!(err, StoreError::Malformed { .. }),
        "expected Malformed, got {err:?}"
    );
    assert_eq!(
        fs::read(dir.path().join(PRIVATE)).unwrap(),
        b"this is not a key",
        "reading must not touch the file"
    );
}

// ---------------------------------------------------------------------------
// Tests: first run
// ---------------------------------------------------------------------------

#[test]
fn first_run_creates_the_dir_generates_and_persists_a_reloadable_key() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("nested").join(".android");

    let key = store::load_or_generate(&dir, &mut OsRng, NAME).unwrap();

    let pub_file = fs::read(dir.join(PUBLIC)).unwrap();
    assert_eq!(
        pub_file,
        &key.public_key_wire()[..key.public_key_wire().len() - 1],
        "adbkey.pub holds the wire blob without its NUL, as adb writes it"
    );

    let reloaded = store::load(&dir, &mut OsRng, NAME).unwrap();
    assert_eq!(
        reloaded.public_key_wire(),
        key.public_key_wire(),
        "what was generated must come back on the next run"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&dir.join(PRIVATE)),
            0o600,
            "the private key is readable by its owner only"
        );
        // `mkdir` filters the mode through the umask, so the exact bits
        // are the caller's business; what must hold is that the
        // directory is closed to everyone else.
        assert_eq!(
            mode(&dir) & 0o007,
            0,
            "the directory holding it is closed to others"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_key_directory_that_cannot_be_created_is_reported_by_name() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o500)).unwrap();
    // Nothing to read, so the store goes on to create the directory —
    // and cannot, because the parent forbids it.
    let dir = parent.path().join("android");
    if fs::create_dir(parent.path().join("probe")).is_ok() {
        return; // running as root, where the mode bits mean nothing
    }

    let err = store::load_or_generate(&dir, &mut OsRng, NAME).unwrap_err();

    let StoreError::Io { path, .. } = &err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(
        path, &dir,
        "the directory is what failed, so it is what the error names"
    );
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn concurrent_first_runs_converge_on_one_key() {
    // Generation is slow enough for a second process — `adb` itself,
    // say — to finish first. Whoever gets there wins, and everyone
    // else adopts that key rather than replacing it: the device may
    // already have been asked to trust it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();

    let racers: Vec<_> = (0..4)
        .map(|_| {
            let dir = path.clone();
            std::thread::spawn(move || {
                store::load_or_generate(&dir, &mut OsRng, NAME)
                    .unwrap()
                    .public_key_wire()
                    .to_vec()
            })
        })
        .collect();
    let keys: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();

    let winner = store::load(&path, &mut OsRng, NAME).unwrap();
    for key in &keys {
        assert_eq!(
            key,
            winner.public_key_wire(),
            "every racer must end up with the key that is on disk"
        );
    }
    let leftovers: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n != PRIVATE && n != PUBLIC)
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temporaries survive: {leftovers:?}"
    );
}

#[test]
fn load_or_generate_reuses_an_existing_key_and_rewrites_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), PKCS8_PEM).unwrap();
    fs::write(dir.path().join(PUBLIC), b"sentinel not-a-key").unwrap();
    let expected = store::load(dir.path(), &mut OsRng, NAME).unwrap();

    let key = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap();

    assert_eq!(
        key.public_key_wire(),
        expected.public_key_wire(),
        "a device that trusts this key must keep trusting it"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(PRIVATE)).unwrap(),
        PKCS8_PEM,
        "an existing key is left byte-for-byte alone"
    );
    assert_eq!(
        fs::read(dir.path().join(PUBLIC)).unwrap(),
        b"sentinel not-a-key",
        "and the public file is neither read nor rewritten"
    );
}

#[test]
fn load_or_generate_restores_a_missing_pub_file_beside_an_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), PKCS8_PEM).unwrap();

    let key = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap();

    assert_eq!(
        fs::read(dir.path().join(PUBLIC)).unwrap(),
        &key.public_key_wire()[..key.public_key_wire().len() - 1],
        "the derived public file is written for other tools to find"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(PRIVATE)).unwrap(),
        PKCS8_PEM,
        "without disturbing the key itself"
    );
}

#[test]
fn an_adbkey_that_cannot_be_read_is_reported_rather_than_replaced() {
    let dir = tempfile::tempdir().unwrap();
    // A directory in the key's place: reading it fails for a reason
    // that is not "no key here yet".
    fs::create_dir(dir.path().join(PRIVATE)).unwrap();

    let err = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap_err();

    assert!(
        matches!(&err, StoreError::Io { source, .. } if source.kind() != ErrorKind::NotFound),
        "only a missing key may lead to generation, got {err:?}"
    );
    assert!(
        dir.path().join(PRIVATE).is_dir(),
        "whatever was in the way is still there"
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_adbkey_survives_load_or_generate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(PRIVATE);
    fs::write(&path, PKCS8_PEM).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_to_string(&path).is_ok() {
        return; // running as root, where the mode bits mean nothing
    }

    let err = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap_err();

    assert!(
        matches!(&err, StoreError::Io { source, .. } if source.kind() != ErrorKind::NotFound),
        "expected the read failure to surface, got {err:?}"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        PKCS8_PEM,
        "a key we merely failed to read must not be replaced by a new one"
    );
}

#[test]
fn a_binary_adbkey_is_the_file_s_fault_not_the_filesystem_s() {
    let dir = tempfile::tempdir().unwrap();
    // Valid DER, say, where PEM belongs: not text, so not a key file.
    fs::write(dir.path().join(PRIVATE), [0x30, 0x82, 0xFF, 0xFE]).unwrap();

    let err = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap_err();

    assert!(
        matches!(err, StoreError::NotAKeyFile { .. }),
        "expected NotAKeyFile, got {err:?}"
    );
    assert_eq!(
        fs::read(dir.path().join(PRIVATE)).unwrap(),
        [0x30, 0x82, 0xFF, 0xFE],
        "and it is left where it was"
    );
}

#[test]
fn a_key_left_without_its_public_file_gets_one_on_the_next_run() {
    // What a writer that died between publishing the key and deriving
    // its public file leaves behind.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), PKCS8_PEM).unwrap();

    let key = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap();

    assert_eq!(
        fs::read(dir.path().join(PUBLIC)).unwrap(),
        key.public_key_line(),
        "the derived file is restored beside the key"
    );
}

#[test]
fn a_corrupt_adbkey_is_never_overwritten_by_load_or_generate() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(PRIVATE), b"this is not a key").unwrap();

    let err = store::load_or_generate(dir.path(), &mut OsRng, NAME).unwrap_err();

    assert!(
        matches!(err, StoreError::Malformed { .. }),
        "expected Malformed, got {err:?}"
    );
    assert_eq!(
        fs::read(dir.path().join(PRIVATE)).unwrap(),
        b"this is not a key",
        "generating over an unreadable identity would strand the user"
    );
    let left: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, [PRIVATE], "and no half-written files are left behind");
}
