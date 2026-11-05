use core::future::Future;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

use embedded_io_async::{Read, Write};

use super::BlockingTcp;
use crate::transport::{ReadCancelSafety, Splittable};

/// One poll is all a blocking transport ever needs.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = core::pin::pin!(fut);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(v) => v,
        core::task::Poll::Pending => panic!("a blocking transport never parks"),
    }
}

/// A connected pair: the host's socket and the device's end of it.
fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let host = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (device, _) = listener.accept().unwrap();
    (host, device)
}

#[test]
fn the_halves_of_a_split_share_one_connection() {
    let (host, mut device) = connected();
    let (mut rx, mut tx) = BlockingTcp::new(host).split().unwrap();

    block_on(tx.write_all(b"ping")).unwrap();
    block_on(tx.flush()).unwrap();
    let mut got = [0u8; 4];
    device.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");

    device.write_all(b"pong").unwrap();
    let mut got = [0u8; 4];
    block_on(rx.read_exact(&mut got)).unwrap();
    assert_eq!(&got, b"pong");
}

#[test]
fn wrapping_a_socket_leaves_its_options_alone() {
    let (host, _device) = connected();
    host.set_nodelay(false).unwrap();
    let tcp = BlockingTcp::new(host);
    assert!(!tcp.get_ref().nodelay().unwrap());
    tcp.get_ref().set_nodelay(true).unwrap();
    assert!(
        tcp.get_ref().nodelay().unwrap(),
        "get_ref is the socket itself"
    );
}

/// Claiming otherwise promises a race that cannot run: the read parks
/// the thread in its first poll, and the interrupt is not polled again
/// until bytes arrive.
#[test]
fn a_read_is_not_raced_against_an_interrupt() {
    let (host, _device) = connected();
    assert!(!BlockingTcp::new(host).read_cancel_safe());
}
