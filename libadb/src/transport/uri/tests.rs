use super::*;

#[test]
fn tcp_ipv4() {
    assert_eq!(
        parse("tcp://127.0.0.1:5555"),
        Ok(Uri::Tcp {
            host: "127.0.0.1",
            port: 5555
        }),
    );
}

#[test]
fn tcp_hostname() {
    assert_eq!(
        parse("tcp://android.local:5555"),
        Ok(Uri::Tcp {
            host: "android.local",
            port: 5555
        }),
    );
}

#[test]
fn tcp_ipv6_bracketed() {
    assert_eq!(
        parse("tcp://[::1]:5555"),
        Ok(Uri::Tcp {
            host: "::1",
            port: 5555
        }),
    );
}

#[test]
fn tcp_ipv6_full() {
    assert_eq!(
        parse("tcp://[fe80::1234:5678]:5555"),
        Ok(Uri::Tcp {
            host: "fe80::1234:5678",
            port: 5555
        }),
    );
}

#[test]
fn tcp_port_boundary() {
    assert_eq!(parse("tcp://h:0"), Ok(Uri::Tcp { host: "h", port: 0 }),);
    assert_eq!(
        parse("tcp://h:65535"),
        Ok(Uri::Tcp {
            host: "h",
            port: 65535
        }),
    );
}

#[test]
fn tcp_missing_port() {
    assert_eq!(parse("tcp://host"), Err(UriError::InvalidPort));
}

#[test]
fn tcp_empty_host_v4() {
    assert_eq!(parse("tcp://:5555"), Err(UriError::InvalidHost));
}

#[test]
fn tcp_empty_body() {
    assert_eq!(parse("tcp://"), Err(UriError::InvalidHost));
}

#[test]
fn tcp_port_out_of_range() {
    assert_eq!(parse("tcp://host:99999"), Err(UriError::InvalidPort));
}

#[test]
fn tcp_port_non_numeric() {
    assert_eq!(parse("tcp://host:abc"), Err(UriError::InvalidPort));
}

#[test]
fn a_port_with_a_sign_is_not_a_port() {
    assert_eq!(parse("tcp://host:+5555"), Err(UriError::InvalidPort));
    assert_eq!(parse("tcp://[::1]:+5555"), Err(UriError::InvalidPort));
}

#[test]
fn a_usb_id_with_a_sign_is_not_four_hex_digits() {
    assert_eq!(parse("usb://+8d1:4ee7"), Err(UriError::InvalidUsbSelector));
    assert_eq!(parse("usb://18d1:+ee7"), Err(UriError::InvalidUsbSelector));
}

#[test]
fn tcp_bare_ipv6_rejected() {
    assert_eq!(parse("tcp://::1:5555"), Err(UriError::InvalidHost));
}

#[test]
fn tcp_ipv6_unclosed() {
    assert_eq!(parse("tcp://[::1:5555"), Err(UriError::InvalidHost));
}

#[test]
fn tcp_ipv6_empty_host() {
    assert_eq!(parse("tcp://[]:5555"), Err(UriError::InvalidHost));
}

#[test]
fn tcp_ipv6_missing_port() {
    assert_eq!(parse("tcp://[::1]"), Err(UriError::InvalidPort));
}

#[test]
fn tcp_ipv6_bogus_after_bracket() {
    assert_eq!(parse("tcp://[::1]x5555"), Err(UriError::InvalidPort));
}

#[test]
fn usb_any() {
    assert_eq!(parse("usb://"), Ok(Uri::Usb(UsbSelector::Any)));
}

#[test]
fn usb_vid_pid_lower() {
    assert_eq!(
        parse("usb://18d1:4ee7"),
        Ok(Uri::Usb(UsbSelector::VidPid {
            vid: 0x18d1,
            pid: 0x4ee7
        })),
    );
}

#[test]
fn usb_vid_pid_upper() {
    assert_eq!(
        parse("usb://18D1:4EE7"),
        Ok(Uri::Usb(UsbSelector::VidPid {
            vid: 0x18D1,
            pid: 0x4EE7
        })),
    );
}

#[test]
fn usb_serial() {
    assert_eq!(
        parse("usb://serial/ABC123XYZ"),
        Ok(Uri::Usb(UsbSelector::Serial("ABC123XYZ"))),
    );
}

#[test]
fn usb_empty_serial() {
    assert_eq!(parse("usb://serial/"), Err(UriError::InvalidUsbSelector));
}

#[test]
fn usb_short_vid() {
    assert_eq!(parse("usb://18d:4ee7"), Err(UriError::InvalidUsbSelector));
}

#[test]
fn usb_long_pid() {
    assert_eq!(parse("usb://18d1:4ee7a"), Err(UriError::InvalidUsbSelector));
}

#[test]
fn usb_non_hex() {
    assert_eq!(parse("usb://ghij:4ee7"), Err(UriError::InvalidUsbSelector));
}

#[test]
fn usb_missing_colon() {
    assert_eq!(parse("usb://18d1"), Err(UriError::InvalidUsbSelector));
}

#[test]
fn missing_scheme_empty() {
    assert_eq!(parse(""), Err(UriError::MissingScheme));
}

#[test]
fn missing_scheme_plain() {
    assert_eq!(parse("127.0.0.1:5555"), Err(UriError::MissingScheme));
}

#[test]
fn unknown_scheme() {
    assert_eq!(parse("ftp://host:21"), Err(UriError::UnknownScheme));
}

#[test]
fn scheme_case_sensitive() {
    assert_eq!(parse("TCP://host:5555"), Err(UriError::UnknownScheme));
}
