#![cfg(any(feature = "tokio", feature = "smol"))]

use libadb::cmd;

#[path = "rt/rt.rs"]
mod rt;

#[path = "fake_device/fake_device.rs"]
mod fake_device;
use fake_device::{session, FakeDevice};

#[path = "common/mod.rs"]
mod common;
#[cfg(unix)]
use common::{shell_v2_encode, SH_EXIT};

/// Arguments a shell would take apart if they reached it unquoted.
const ARGS: &[&str] = &[
    "package",
    "install",
    "/sdcard/My App.apk",
    ";printf injected",
    "$(id)",
    "it's",
    "a|b",
    "",
    "a\nb",
];

/// Run the `sh -c` string `adbd` would run, with `cmd` replaced by a
/// function that reports the argv it was handed.
///
/// Unix only: there is no `sh` to hold to account elsewhere. The `abb`
/// test below carries the same expectation on every platform.
#[cfg(unix)]
fn argv_via_sh(command: &str) -> Vec<Vec<u8>> {
    use std::process::Command;

    let script = format!("cmd() {{ for a in \"$@\"; do printf '%s\\0' \"$a\"; done; }}\n{command}");
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run /bin/sh");
    assert!(out.status.success(), "sh failed: {out:?}");
    split_nul(&out.stdout)
}

/// Split NUL-terminated records, dropping the empty tail the final
/// terminator leaves behind.
fn split_nul(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut parts: Vec<Vec<u8>> = bytes.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
    parts.pop();
    parts
}

fn expected() -> Vec<Vec<u8>> {
    ARGS.iter().map(|a| a.as_bytes().to_vec()).collect()
}

rt_test! {
#[cfg(unix)]
async fn the_shell_path_hands_the_device_the_arguments_it_was_given() {
    let dev = FakeDevice::new().banner(b"device::features=shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2", |mut s| async move {
        let (mut ch, dest) = s.accept_open_any().await;
        ch.send_write(&shell_v2_encode(SH_EXIT, &[0])).await;
        ch.expect_ack().await;
        ch.expect_close().await;
        dest
    })
    .await;

    let mut rx = [0u8; 4096];
    cmd::exec(&mut conn, ARGS, &mut rx).await.unwrap();
    let dest = rt::join(device).await;

    let dest = core::str::from_utf8(&dest).unwrap();
    let command = dest
        .strip_prefix("shell,v2,raw:")
        .and_then(|d| d.strip_suffix('\0'))
        .unwrap_or_else(|| panic!("unexpected destination {dest:?}"));

    assert_eq!(argv_via_sh(command), expected());
}
}

rt_test! {
async fn the_abb_path_agrees_with_the_shell_path() {
    let dev = FakeDevice::new().banner(b"device::features=abb_exec,shell_v2".to_vec());
    let (mut conn, device) = session(dev, b"host::features=shell_v2,abb_exec", |mut s| async move {
        let (mut ch, dest) = s.accept_open_any().await;
        ch.send_close().await;
        dest
    })
    .await;

    let mut rx = [0u8; 4096];
    cmd::exec(&mut conn, ARGS, &mut rx).await.unwrap();
    let dest = rt::join(device).await;

    let args = dest
        .strip_prefix(b"abb_exec:".as_slice())
        .unwrap_or_else(|| panic!("unexpected destination {dest:?}"));

    assert_eq!(split_nul(args), expected());
}
}
