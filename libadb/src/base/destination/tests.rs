use super::*;
use alloc::format;
use alloc::string::String;

const CMD: &[&[u8]] = &[b"shell,v2,raw:cmd"];

fn rendered(args: &[&str]) -> String {
    let mut buf = [0u8; 256];
    let len = write_destination(&mut buf, CMD, args).unwrap();
    assert_eq!(buf[len - 1], 0, "destination must stay NUL-terminated");
    String::from_utf8(buf[..len - 1].to_vec()).unwrap()
}

#[test]
fn shell_safe_arguments_stay_bare() {
    assert_eq!(
        rendered(&["package", "list", "packages"]),
        "shell,v2,raw:cmd package list packages"
    );
    assert_eq!(
        rendered(&[
            "--user=0",
            "-l",
            "a,b",
            "/data/local/tmp/x.apk",
            "a.b:c%d+e@f"
        ]),
        "shell,v2,raw:cmd --user=0 -l a,b /data/local/tmp/x.apk a.b:c%d+e@f"
    );
}

#[test]
fn spaces_do_not_split_an_argument() {
    assert_eq!(
        rendered(&["install", "/sdcard/My App.apk"]),
        "shell,v2,raw:cmd install '/sdcard/My App.apk'"
    );
}

#[test]
fn shell_metacharacters_lose_their_meaning() {
    for evil in [
        ";reboot",
        "a|b",
        "x&&y",
        "$(id)",
        "`id`",
        ">/data/local/tmp/pwn",
        "*",
        "~root",
        "a\nb",
        "#comment",
    ] {
        assert_eq!(
            rendered(&["arg", evil]),
            format!("shell,v2,raw:cmd arg '{evil}'"),
            "{evil:?} must be quoted whole"
        );
    }
}

#[test]
fn single_quotes_are_escaped() {
    assert_eq!(rendered(&["it's"]), r"shell,v2,raw:cmd 'it'\''s'");
    assert_eq!(rendered(&["'"]), r"shell,v2,raw:cmd ''\'''");
}

#[test]
fn non_ascii_is_quoted_but_intact() {
    assert_eq!(rendered(&["привет"]), "shell,v2,raw:cmd 'привет'");
}

#[test]
fn an_empty_argument_survives() {
    assert_eq!(rendered(&["set", "", "x"]), "shell,v2,raw:cmd set '' x");
}

#[test]
fn a_nul_in_an_argument_is_rejected() {
    let mut buf = [0u8; 256];
    assert_eq!(
        write_destination(&mut buf, CMD, &["a\0b"]),
        Err(DestinationError::Nul)
    );
}

#[test]
fn a_nul_in_a_prefix_is_rejected() {
    let mut buf = [0u8; 256];
    assert_eq!(
        write_destination(&mut buf, &[b"shell:", b"cat /x\0; rm -rf /"], &[]),
        Err(DestinationError::Nul)
    );
}

#[test]
fn a_nul_outranks_a_buffer_that_is_too_small() {
    let mut buf = [0u8; 4];
    assert_eq!(
        write_destination(&mut buf, CMD, &["a\0b"]),
        Err(DestinationError::Nul)
    );
}

#[test]
fn a_full_buffer_is_reported_as_too_long() {
    let mut buf = [0u8; 10];
    assert_eq!(
        write_destination(&mut buf, CMD, &["package"]),
        Err(DestinationError::TooLong)
    );
}

#[test]
fn the_quotes_themselves_are_counted_against_the_buffer() {
    // Exactly enough for `p:` + ` a b` + NUL, but the quoting the
    // space forces needs two bytes more.
    let mut buf = [0u8; 7];
    assert_eq!(
        write_destination(&mut buf, &[b"p:"], &["a b"]),
        Err(DestinationError::TooLong)
    );
    let mut buf = [0u8; 9];
    let len = write_destination(&mut buf, &[b"p:"], &["a b"]).unwrap();
    assert_eq!(&buf[..len], b"p: 'a b'\0");
}
