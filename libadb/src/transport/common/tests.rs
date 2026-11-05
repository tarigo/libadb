use super::{NoUsb, Transport, TransportError};
use crate::transport::Splittable;
use alloc::format;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use embedded_io::{ErrorKind, ErrorType};
use embedded_io_async::{Read, Write};

fn poll_ready<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("mock future returned Pending"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MockErr(&'static str);

impl embedded_io::Error for MockErr {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidData
    }
}

impl core::error::Error for MockErr {}

impl core::fmt::Display for MockErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Default)]
struct MockIo {
    read_result: Option<Result<&'static [u8], MockErr>>,
    write_result: Option<Result<usize, MockErr>>,
    flush_result: Option<Result<(), MockErr>>,
    split_err: Option<MockErr>,
}

impl ErrorType for MockIo {
    type Error = MockErr;
}

impl Read for MockIo {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockErr> {
        match self.read_result.take().expect("read_result not set") {
            Ok(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for MockIo {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, MockErr> {
        self.write_result.take().expect("write_result not set")
    }

    async fn flush(&mut self) -> Result<(), MockErr> {
        self.flush_result.take().expect("flush_result not set")
    }
}

impl crate::transport::ReadCancelSafety for MockIo {
    fn read_cancel_safe(&self) -> bool {
        true
    }
}

impl Splittable for MockIo {
    type ReadHalf = MockIo;
    type WriteHalf = MockIo;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), MockErr> {
        if let Some(e) = self.split_err {
            Err(e)
        } else {
            Ok((MockIo::default(), MockIo::default()))
        }
    }
}

#[test]
fn transport_error_tcp_display_prefixes_inner_with_tcp() {
    let e: TransportError<MockErr, MockErr> = TransportError::Tcp(MockErr("oops"));
    assert_eq!(format!("{}", e), "tcp: oops");
}

#[test]
fn transport_error_tcp_kind_delegates_to_inner() {
    let e: TransportError<MockErr, MockErr> = TransportError::Tcp(MockErr("x"));
    assert_eq!(embedded_io::Error::kind(&e), ErrorKind::InvalidData);
}

#[test]
fn transport_tcp_read_delegates_and_returns_byte_count() {
    let inner = MockIo {
        read_result: Some(Ok(b"hello")),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    let mut buf = [0u8; 8];
    let n = poll_ready(t.read(&mut buf)).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"hello");
}

#[test]
fn transport_tcp_read_wraps_inner_error_as_tcp_variant() {
    let inner = MockIo {
        read_result: Some(Err(MockErr("broken"))),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    let mut buf = [0u8; 8];
    let err = poll_ready(t.read(&mut buf)).unwrap_err();
    assert!(matches!(err, TransportError::Tcp(MockErr("broken"))));
}

#[test]
fn transport_tcp_write_delegates_and_returns_byte_count() {
    let inner = MockIo {
        write_result: Some(Ok(3)),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    let n = poll_ready(t.write(b"abc")).unwrap();
    assert_eq!(n, 3);
}

#[test]
fn transport_tcp_write_wraps_inner_error_as_tcp_variant() {
    let inner = MockIo {
        write_result: Some(Err(MockErr("nope"))),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    let err = poll_ready(t.write(b"x")).unwrap_err();
    assert!(matches!(err, TransportError::Tcp(MockErr("nope"))));
}

#[test]
fn transport_tcp_flush_delegates_to_inner() {
    let inner = MockIo {
        flush_result: Some(Ok(())),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    poll_ready(t.flush()).unwrap();
}

#[test]
fn transport_tcp_flush_wraps_inner_error_as_tcp_variant() {
    let inner = MockIo {
        flush_result: Some(Err(MockErr("flush-fail"))),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    let err = poll_ready(t.flush()).unwrap_err();
    assert!(matches!(err, TransportError::Tcp(MockErr("flush-fail"))));
}

#[test]
fn transport_tcp_split_wraps_halves_as_tcp_variants() {
    let t: Transport<MockIo, MockIo> = Transport::Tcp(MockIo::default());
    let (r, w) = t.split().expect("split ok");
    assert!(matches!(r, Transport::Tcp(_)));
    assert!(matches!(w, Transport::Tcp(_)));
}

#[test]
fn transport_usb_read_delegates_and_returns_byte_count() {
    let inner = MockIo {
        read_result: Some(Ok(b"from usb")),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Usb(inner);
    let mut buf = [0u8; 16];
    let n = poll_ready(t.read(&mut buf)).unwrap();
    assert_eq!(&buf[..n], b"from usb");
}

#[test]
fn transport_usb_write_wraps_inner_error_as_usb_variant() {
    let inner = MockIo {
        write_result: Some(Err(MockErr("usb down"))),
        ..MockIo::default()
    };
    let mut t: Transport<MockIo, MockIo> = Transport::Usb(inner);
    let err = poll_ready(t.write(b"x")).unwrap_err();
    assert!(matches!(err, TransportError::Usb(MockErr("usb down"))));
}

#[test]
fn transport_usb_split_wraps_halves_as_usb_variants() {
    let t: Transport<MockIo, MockIo> = Transport::Usb(MockIo::default());
    let (r, w) = t.split().expect("split ok");
    assert!(matches!(r, Transport::Usb(_)));
    assert!(matches!(w, Transport::Usb(_)));
}

#[test]
fn no_usb_leaves_the_usb_variant_unconstructible() {
    // The variant exists unconditionally, but `NoUsb` has no values,
    // so a build without a USB backend simply cannot reach it.
    let t: Transport<MockIo, NoUsb> = Transport::Tcp(MockIo::default());
    match t {
        Transport::Tcp(_) => {}
        Transport::Usb(never) => match never {},
    }
}

#[test]
fn transport_tcp_split_wraps_inner_error_as_tcp_variant() {
    let inner = MockIo {
        split_err: Some(MockErr("split-fail")),
        ..MockIo::default()
    };
    let t: Transport<MockIo, MockIo> = Transport::Tcp(inner);
    match t.split() {
        Ok(_) => panic!("expected split to fail"),
        Err(TransportError::Tcp(MockErr("split-fail"))) => {}
        Err(other) => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn a_transport_error_keeps_its_cause_reachable() {
    use core::error::Error as _;

    let e: TransportError<MockErr, MockErr> = TransportError::Tcp(MockErr("oops"));
    let source = e.source().expect("the transport error is the cause");
    assert_eq!(format!("{source}"), "oops");

    let e: TransportError<MockErr, MockErr> = TransportError::Usb(MockErr("nope"));
    assert!(e.source().is_some(), "the usb half has a cause too");
}
