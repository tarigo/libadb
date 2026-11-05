use core::future::Future;
use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

use embedded_io_async::{Read, Write};

use super::blocking::past_signals;
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

#[test]
fn a_call_is_made_again_for_a_signal_and_for_nothing_else() {
    use std::io::{Error, ErrorKind};

    let mut calls = 0;
    let done = past_signals(|| {
        calls += 1;
        match calls {
            1 | 2 => Err(Error::from(ErrorKind::Interrupted)),
            _ => Ok(calls),
        }
    });
    assert_eq!(done.unwrap(), 3);

    for kind in [
        ErrorKind::WouldBlock,
        ErrorKind::TimedOut,
        ErrorKind::ConnectionReset,
    ] {
        let mut calls = 0;
        let failed = past_signals(|| -> std::io::Result<()> {
            calls += 1;
            Err(Error::from(kind))
        });
        assert_eq!(failed.unwrap_err().kind(), kind);
        assert_eq!(calls, 1, "{kind:?} is an answer, not an interruption");
    }
}

/// On a thread of its own, as a timeout retried would never end the read.
#[test]
fn a_timeout_still_ends_a_read() {
    let (host, _device) = connected();
    host.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let mut tcp = BlockingTcp::new(host);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut got = [0u8; 4];
        let _ = tx.send(block_on(tcp.read(&mut got)).map_err(|e| e.kind()));
    });

    let read = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the timeout did not end the read");
    assert!(
        matches!(
            read,
            Err(std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        ),
        "got {read:?}"
    );
}

/// With a real signal, on the very thread blocked in the socket call.
/// The handler goes in without `SA_RESTART`, which is also how any
/// handler behaves once the socket has a timeout.
#[cfg(unix)]
#[allow(unsafe_code)]
mod real_signals {
    use alloc::vec;
    use core::time::Duration;
    use std::io::{Read as _, Write as _};
    use std::sync::{mpsc, Once};
    use std::thread;

    use embedded_io_async::{Read, Write};

    use super::{block_on, connected, BlockingTcp};

    /// Nothing else in the test binary touches this one.
    const SIGNAL: libc::c_int = libc::SIGUSR2;

    extern "C" fn does_nothing(_signal: libc::c_int) {}

    fn install_handler() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            // SAFETY: zeroed is a valid `sigaction`, and the handler
            // does nothing, which is async-signal-safe.
            unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = does_nothing as extern "C" fn(libc::c_int) as usize;
                assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
                assert_eq!(
                    libc::sigaction(SIGNAL, &action, core::ptr::null_mut()),
                    0,
                    "{}",
                    std::io::Error::last_os_error()
                );
            }
        });
    }

    /// Signal `thread` for long enough for it to be blocked by the time
    /// the last ones land. There is no way to ask, and one that lands
    /// early costs nothing: the test then just proves less.
    fn interrupt(thread: libc::pthread_t) {
        for _ in 0..25 {
            // SAFETY: the thread is alive, or not yet joined.
            assert_eq!(unsafe { libc::pthread_kill(thread, SIGNAL) }, 0);
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// This thread's id, for [`interrupt`], on `tx`.
    fn report_this_thread(tx: mpsc::Sender<libc::pthread_t>) {
        // SAFETY: `pthread_self` has no preconditions.
        tx.send(unsafe { libc::pthread_self() }).unwrap();
    }

    #[test]
    fn a_signal_does_not_end_a_blocked_read() {
        install_handler();
        let (host, mut device) = connected();
        let mut tcp = BlockingTcp::new(host);

        let (tx, rx) = mpsc::channel();
        let reading = thread::spawn(move || {
            report_this_thread(tx);
            let mut got = [0u8; 4];
            let n = block_on(tcp.read(&mut got))?;
            std::io::Result::Ok(got[..n].to_vec())
        });

        interrupt(rx.recv().unwrap());
        device.write_all(b"pong").unwrap();
        assert_eq!(reading.join().unwrap().unwrap(), b"pong");
    }

    /// A write that took nothing yet is the one a signal fails outright:
    /// one that has moved bytes returns their count instead. Hence the
    /// socket filled up first.
    #[test]
    fn a_signal_does_not_end_a_blocked_write() {
        install_handler();
        let (host, mut device) = connected();
        let mut sent = 0;
        host.set_nonblocking(true).unwrap();
        loop {
            match (&host).write(&[0xA5; 64 * 1024]) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling the socket: {e}"),
            }
        }
        host.set_nonblocking(false).unwrap();
        let mut tcp = BlockingTcp::new(host);

        let (tx, rx) = mpsc::channel();
        let writing = thread::spawn(move || {
            report_this_thread(tx);
            block_on(tcp.write(&[0x5A]))
        });

        interrupt(rx.recv().unwrap());
        let mut drained = vec![0u8; sent + 1];
        device.read_exact(&mut drained).unwrap();
        assert_eq!(writing.join().unwrap().unwrap(), 1);
        assert_eq!(drained.last(), Some(&0x5A));
    }
}
