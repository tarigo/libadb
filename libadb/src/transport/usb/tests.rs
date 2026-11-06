use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// A connect error that names which step failed.
#[derive(Debug, PartialEq)]
enum Fail {
    NotFound,
    NoAdbInterface,
    Ids,
    Interfaces,
    Serial,
    Open,
}

impl ScanError for Fail {
    fn not_found() -> Self {
        Self::NotFound
    }

    fn no_adb_interface() -> Self {
        Self::NoAdbInterface
    }
}

struct Dev {
    vid: u16,
    pid: u16,
    serial: Option<&'static str>,
    adb: Option<u8>,
    interfaces_unreadable: bool,
    serial_unreadable: bool,
}

impl Dev {
    fn new(vid: u16, pid: u16, adb: Option<u8>) -> Self {
        Self {
            vid,
            pid,
            serial: None,
            adb,
            interfaces_unreadable: false,
            serial_unreadable: false,
        }
    }

    fn with_serial(mut self, serial: &'static str) -> Self {
        self.serial = Some(serial);
        self
    }

    fn with_unreadable_interfaces(mut self) -> Self {
        self.interfaces_unreadable = true;
        self
    }

    fn with_unreadable_serial(mut self) -> Self {
        self.serial_unreadable = true;
        self
    }
}

impl Enumerated for Dev {
    type Error = Fail;
    type Interface = u8;

    fn vid(&self) -> u16 {
        self.vid
    }

    fn pid(&self) -> u16 {
        self.pid
    }

    fn adb_interface(&self) -> Result<Option<u8>, Fail> {
        if self.interfaces_unreadable {
            return Err(Fail::Interfaces);
        }
        Ok(self.adb)
    }

    fn serial(&mut self) -> Result<Option<String>, Fail> {
        if self.serial_unreadable {
            return Err(Fail::Serial);
        }
        Ok(self.serial.map(String::from))
    }
}

/// Scan that reports which device was picked, by pid.
fn pick(devices: Vec<Dev>, selector: UsbSelector<'_>) -> Result<(u16, u8), Fail> {
    pick_among(devices.into_iter().map(Ok).collect(), selector)
}

/// [`pick`] among devices some of which could not be read.
fn pick_among(
    devices: Vec<Result<Dev, Fail>>,
    selector: UsbSelector<'_>,
) -> Result<(u16, u8), Fail> {
    scan(devices, selector, |d, iface| Ok((d.pid, iface)))
}

#[test]
fn any_walks_past_a_device_without_an_adb_interface() {
    let devices = vec![
        Dev::new(0xf00d, 0x0001, None),
        Dev::new(0xf00d, 0x0002, None),
        Dev::new(0xbeef, 0x0001, Some(1)),
    ];
    assert_eq!(pick(devices, UsbSelector::Any), Ok((0x0001, 1)));
}

#[test]
fn any_finds_nothing_when_no_device_speaks_adb() {
    let devices = vec![Dev::new(0xf00d, 0x0001, None)];
    assert_eq!(pick(devices, UsbSelector::Any), Err(Fail::NotFound));
}

#[test]
fn vid_pid_ignores_other_devices() {
    let devices = vec![
        Dev::new(0xf00d, 0x0001, Some(0)),
        Dev::new(0xbeef, 0x0001, Some(2)),
    ];
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    assert_eq!(pick(devices, selector), Ok((0x0001, 2)));
}

#[test]
fn a_vid_pid_has_to_match_both_halves() {
    let selector = UsbSelector::VidPid {
        vid: 0x18d1,
        pid: 0x4ee7,
    };
    let same_vid = vec![Dev::new(0x18d1, 0x4ee8, Some(0))];
    assert_eq!(pick(same_vid, selector), Err(Fail::NotFound));
    let same_pid = vec![Dev::new(0x18d2, 0x4ee7, Some(0))];
    assert_eq!(pick(same_pid, selector), Err(Fail::NotFound));
}

#[test]
fn a_named_device_without_an_adb_interface_says_so() {
    let devices = vec![Dev::new(0xbeef, 0x0001, None)];
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    assert_eq!(pick(devices, selector), Err(Fail::NoAdbInterface));
}

#[test]
fn a_serial_picks_its_own_device() {
    let devices = vec![
        Dev::new(0xbeef, 0x0001, Some(0)).with_serial("OTHER"),
        Dev::new(0xbeef, 0x0001, Some(1)),
        Dev::new(0xbeef, 0x0001, Some(2)).with_serial("WANTED"),
    ];
    assert_eq!(
        pick(devices, UsbSelector::Serial("WANTED")),
        Ok((0x0001, 2))
    );
}

/// Reading a serial may mean opening the device under libusb, so a
/// selector that names none must not ask: the devices here would fail
/// the scan if it did.
#[test]
fn only_a_serial_selector_reads_the_serial() {
    let unreadable = || vec![Dev::new(0xbeef, 0x0001, Some(0)).with_unreadable_serial()];
    assert_eq!(pick(unreadable(), UsbSelector::Any), Ok((0x0001, 0)));
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    assert_eq!(pick(unreadable(), selector), Ok((0x0001, 0)));
}

/// The interface is checked first, so a device that speaks no ADB is
/// never opened to read a serial that could not make it usable.
#[test]
fn a_serial_scan_reads_no_serial_off_a_device_without_adb() {
    let devices = vec![Dev::new(0xf00d, 0x0001, None).with_unreadable_serial()];
    assert_eq!(
        pick(devices, UsbSelector::Serial("WANTED")),
        Err(Fail::NotFound)
    );
}

/// A serial that cannot be read rules out one device, not the search,
/// and is what gets reported when nothing else matches.
#[test]
fn an_unreadable_serial_does_not_end_a_serial_scan() {
    let devices = vec![
        Dev::new(0xbeef, 0x0001, Some(0)).with_unreadable_serial(),
        Dev::new(0xbeef, 0x0002, Some(1)).with_serial("WANTED"),
    ];
    assert_eq!(
        pick(devices, UsbSelector::Serial("WANTED")),
        Ok((0x0002, 1))
    );

    let devices = vec![Dev::new(0xbeef, 0x0001, Some(0)).with_unreadable_serial()];
    assert_eq!(
        pick(devices, UsbSelector::Serial("WANTED")),
        Err(Fail::Serial)
    );
}

/// Interfaces that cannot be read pass a device over in a search, and
/// end the scan when the device was named.
#[test]
fn unreadable_interfaces_fail_only_a_named_device() {
    let devices = || {
        vec![
            Dev::new(0xbeef, 0x0001, Some(0)).with_unreadable_interfaces(),
            Dev::new(0xbeef, 0x0001, Some(1)),
        ]
    };
    assert_eq!(pick(devices(), UsbSelector::Any), Ok((0x0001, 1)));
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    assert_eq!(pick(devices(), selector), Err(Fail::Interfaces));
}

/// Whatever a backend finds wrong with an ADB interface, as rusb finds
/// missing bulk endpoints, turns the device down before it is opened
/// and claimed.
#[test]
fn a_device_its_interfaces_rule_out_is_never_opened() {
    let devices = || {
        vec![
            Ok(Dev::new(0xbeef, 0x0001, Some(0)).with_unreadable_interfaces()),
            Ok(Dev::new(0xbeef, 0x0002, Some(1))),
        ]
    };

    let mut opened = Vec::new();
    let picked = scan(devices(), UsbSelector::Any, |d, _| {
        opened.push(d.pid);
        Ok(d.pid)
    });
    assert_eq!(picked, Ok(0x0002));
    assert_eq!(opened, [0x0002]);

    let mut opened = Vec::new();
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    let picked = scan(devices(), selector, |d, _| {
        opened.push(d.pid);
        Ok(d.pid)
    });
    assert_eq!(picked, Err(Fail::Interfaces));
    assert!(opened.is_empty());
}

/// A device whose IDs cannot be read could be the one wanted or any
/// other, so no selector stops at it, a VID:PID included.
#[test]
fn an_unreadable_device_ends_no_scan() {
    let devices = || {
        vec![
            Err(Fail::Ids),
            Ok(Dev::new(0xbeef, 0x0001, Some(1)).with_serial("WANTED")),
        ]
    };
    let named = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    for selector in [UsbSelector::Any, named, UsbSelector::Serial("WANTED")] {
        assert_eq!(pick_among(devices(), selector), Ok((0x0001, 1)));
    }
}

/// When nothing else matches, the device that could not be read is
/// reported: it may have been the named one, so "not found" would be
/// a guess.
#[test]
fn a_vid_pid_that_matches_nothing_reports_an_unreadable_device() {
    let devices = vec![Err(Fail::Ids), Ok(Dev::new(0xf00d, 0x0002, Some(0)))];
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    assert_eq!(pick_among(devices, selector), Err(Fail::Ids));

    let devices = vec![Err(Fail::Ids)];
    assert_eq!(pick_among(devices, UsbSelector::Any), Err(Fail::Ids));
}

#[test]
fn an_unclaimable_device_does_not_end_an_any_scan() {
    let devices = vec![
        Ok(Dev::new(0xbeef, 0x0001, Some(0))),
        Ok(Dev::new(0xbeef, 0x0002, Some(1))),
    ];
    let mut seen = 0;
    let picked = scan(devices, UsbSelector::Any, |d, iface| {
        seen += 1;
        if d.pid == 0x0001 {
            Err(Fail::Open)
        } else {
            Ok((d.pid, iface))
        }
    });
    assert_eq!(picked, Ok((0x0002, 1)));
    assert_eq!(seen, 2);
}

#[test]
fn the_first_failure_is_reported_when_the_scan_finds_nothing_else() {
    let devices = vec![Ok(Dev::new(0xbeef, 0x0001, Some(0)))];
    let picked: Result<(), _> = scan(devices, UsbSelector::Any, |_, _| Err(Fail::Open));
    assert_eq!(picked, Err(Fail::Open));
}

#[test]
fn a_named_device_surfaces_its_failure_at_once() {
    let devices = vec![
        Ok(Dev::new(0xbeef, 0x0001, Some(0))),
        Ok(Dev::new(0xbeef, 0x0001, Some(1))),
    ];
    let selector = UsbSelector::VidPid {
        vid: 0xbeef,
        pid: 0x0001,
    };
    let mut seen = 0;
    let picked: Result<(), _> = scan(devices, selector, |_, _| {
        seen += 1;
        Err(Fail::Open)
    });
    assert_eq!(picked, Err(Fail::Open));
    assert_eq!(seen, 1);
}

/// Length alone decides: a multiple of the packet size has nothing to
/// end it, multiples of adbd's 16 KiB request included, and any other
/// length ends on its own short packet.
#[test]
fn a_transfer_ends_on_a_packet_boundary_at_a_multiple_of_the_packet_size() {
    for (len, max_packet, on_boundary) in [
        (24, 64, false),
        (511, 64, false),
        (512, 64, true),
        (1024, 64, true),
        (511, 512, false),
        (512, 512, true),
        (513, 512, false),
        (1024, 512, true),
        (4096, 512, true),
        (4097, 512, false),
        (16384, 512, true),
        (16896, 512, true),
        (511, 1024, false),
        (512, 1024, false),
        (1024, 1024, true),
    ] {
        assert_eq!(
            ends_on_packet_boundary(len, max_packet),
            on_boundary,
            "{len} bytes in {max_packet}-byte packets"
        );
    }
}

/// An empty write sends nothing, so it leaves no transfer to end.
#[test]
fn nothing_written_ends_on_no_boundary() {
    for max_packet in [0, 64, 512, 1024] {
        assert!(!ends_on_packet_boundary(0, max_packet));
    }
}

/// A descriptor reporting a packet size of 0 means no zero-length
/// packet, and no division by zero either.
#[test]
fn a_packet_size_of_zero_gives_no_boundary() {
    for len in [0, 511, 512, 1024] {
        assert!(!ends_on_packet_boundary(len, 0));
    }
}
