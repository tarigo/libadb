use embedded_io::{ErrorKind, ErrorType};
use embedded_io_async::{Read, Write};

use crate::transport::Splittable;

/// A transport that is either TCP or USB.
///
/// Both halves are type parameters, so a build may carry several
/// runtimes and several USB backends at once and each call site says
/// which pair it wants. Use [`NoUsb`] for `U` when no backend is
/// compiled in.
pub enum Transport<T, U> {
    Tcp(T),
    Usb(U),
}

/// Stand-in for the USB half of a [`Transport`] in builds without a USB
/// backend. Has no values, so [`Transport::Usb`] is unreachable.
pub enum NoUsb {}

impl ErrorType for NoUsb {
    type Error = NoUsbError;
}

impl Read for NoUsb {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        match *self {}
    }
}

impl Write for NoUsb {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        match *self {}
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match *self {}
    }
}

impl Splittable for NoUsb {
    type ReadHalf = NoUsb;
    type WriteHalf = NoUsb;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        match self {}
    }
}

impl<R> crate::transport::UsbBackend<R> for NoUsb {
    type Transport = NoUsb;
    type Error = NoBackend;

    fn connect_by_selector(_: crate::uri::UsbSelector<'_>) -> Result<NoUsb, NoBackend> {
        Err(NoBackend)
    }
}

/// No USB backend was compiled in, so `usb://` cannot be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoBackend;

impl core::fmt::Display for NoBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no usb backend compiled in")
    }
}

impl core::error::Error for NoBackend {}

/// Error type of [`NoUsb`]; also has no values.
#[derive(Debug)]
pub enum NoUsbError {}

impl core::fmt::Display for NoUsbError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for NoUsbError {}

impl embedded_io::Error for NoUsbError {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

#[derive(Debug)]
pub enum TransportError<E, U> {
    Tcp(E),
    Usb(U),
}

impl<E: core::fmt::Display, U: core::fmt::Display> core::fmt::Display for TransportError<E, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tcp(e) => write!(f, "tcp: {e}"),
            Self::Usb(e) => write!(f, "usb: {e}"),
        }
    }
}

impl<E, U> core::error::Error for TransportError<E, U>
where
    E: core::error::Error + 'static,
    U: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Tcp(e) => Some(e),
            Self::Usb(e) => Some(e),
        }
    }
}

impl<E: embedded_io::Error, U: embedded_io::Error> embedded_io::Error for TransportError<E, U> {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Tcp(e) => embedded_io::Error::kind(e),
            Self::Usb(e) => embedded_io::Error::kind(e),
        }
    }
}

impl<T: ErrorType, U: ErrorType> ErrorType for Transport<T, U> {
    type Error = TransportError<T::Error, U::Error>;
}

impl<T: Read, U: Read> Read for Transport<T, U> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Tcp(t) => Read::read(t, buf).await.map_err(TransportError::Tcp),
            Self::Usb(t) => Read::read(t, buf).await.map_err(TransportError::Usb),
        }
    }
}

impl<T: Write, U: Write> Write for Transport<T, U> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Tcp(t) => Write::write(t, buf).await.map_err(TransportError::Tcp),
            Self::Usb(t) => Write::write(t, buf).await.map_err(TransportError::Usb),
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Tcp(t) => Write::flush(t).await.map_err(TransportError::Tcp),
            Self::Usb(t) => Write::flush(t).await.map_err(TransportError::Usb),
        }
    }
}

impl<T: Splittable, U: Splittable> Splittable for Transport<T, U> {
    type ReadHalf = Transport<T::ReadHalf, U::ReadHalf>;
    type WriteHalf = Transport<T::WriteHalf, U::WriteHalf>;
    fn split(self) -> Result<(Self::ReadHalf, Self::WriteHalf), Self::Error> {
        match self {
            Self::Tcp(t) => {
                let (r, w) = t.split().map_err(TransportError::Tcp)?;
                Ok((Transport::Tcp(r), Transport::Tcp(w)))
            }
            Self::Usb(t) => {
                let (r, w) = t.split().map_err(TransportError::Usb)?;
                Ok((Transport::Usb(r), Transport::Usb(w)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
}
