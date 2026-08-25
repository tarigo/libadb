#![allow(dead_code)]

use std::net::SocketAddr;

#[cfg(feature = "tokio")]
pub use tokio_rt::*;

#[cfg(all(feature = "smol", not(feature = "tokio")))]
pub use smol_rt::*;

pub async fn connect(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.unwrap()
}

pub async fn bind_loopback() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, addr)
}

pub async fn accept_one(l: &TcpListener) -> TcpStream {
    l.accept().await.unwrap().0
}

#[cfg(feature = "tokio")]
mod tokio_rt {
    use std::time::Duration;

    pub use tokio::net::{TcpListener, TcpStream};

    pub type JoinHandle<R> = tokio::task::JoinHandle<R>;
    pub type AdbTransport = libadb::TokioTcp;

    pub fn block_on<F: core::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    pub fn spawn<F>(f: F) -> JoinHandle<F::Output>
    where
        F: core::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(f)
    }

    pub async fn join<R>(h: JoinHandle<R>) -> R {
        h.await.unwrap()
    }

    pub async fn read_exact(s: &mut TcpStream, buf: &mut [u8]) {
        use tokio::io::AsyncReadExt;
        s.read_exact(buf).await.unwrap();
    }

    pub async fn write_all(s: &mut TcpStream, buf: &[u8]) {
        use tokio::io::AsyncWriteExt;
        s.write_all(buf).await.unwrap();
    }

    pub async fn sleep_ms(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    pub async fn timeout_ms<F: core::future::Future>(ms: u64, f: F) -> Option<F::Output> {
        tokio::select! {
            v = f => Some(v),
            _ = tokio::time::sleep(Duration::from_millis(ms)) => None,
        }
    }

    pub async fn join2<F1, F2>(f1: F1, f2: F2) -> (F1::Output, F2::Output)
    where
        F1: core::future::Future,
        F2: core::future::Future,
    {
        tokio::join!(f1, f2)
    }

    pub fn wrap(stream: TcpStream) -> AdbTransport {
        libadb::TokioTcp::new(stream)
    }
}

#[cfg(all(feature = "smol", not(feature = "tokio")))]
mod smol_rt {
    use std::time::Duration;

    pub use smol::net::{TcpListener, TcpStream};

    pub type JoinHandle<R> = smol::Task<R>;
    pub type AdbTransport = libadb::SmolTcp;

    pub fn block_on<F: core::future::Future>(f: F) -> F::Output {
        smol::block_on(f)
    }

    pub fn spawn<F>(f: F) -> JoinHandle<F::Output>
    where
        F: core::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        smol::spawn(f)
    }

    pub async fn join<R>(t: JoinHandle<R>) -> R {
        t.await
    }

    pub async fn read_exact(s: &mut TcpStream, buf: &mut [u8]) {
        use smol::io::AsyncReadExt;
        s.read_exact(buf).await.unwrap();
    }

    pub async fn write_all(s: &mut TcpStream, buf: &[u8]) {
        use smol::io::AsyncWriteExt;
        s.write_all(buf).await.unwrap();
    }

    pub async fn sleep_ms(ms: u64) {
        smol::Timer::after(Duration::from_millis(ms)).await;
    }

    pub async fn timeout_ms<F: core::future::Future>(ms: u64, f: F) -> Option<F::Output> {
        use smol::future::FutureExt;
        let body = async { Some(f.await) };
        let deadline = async {
            smol::Timer::after(Duration::from_millis(ms)).await;
            None
        };
        body.or(deadline).await
    }

    pub async fn join2<F1, F2>(f1: F1, f2: F2) -> (F1::Output, F2::Output)
    where
        F1: core::future::Future,
        F2: core::future::Future,
    {
        smol::future::zip(f1, f2).await
    }

    pub fn wrap(stream: TcpStream) -> AdbTransport {
        libadb::SmolTcp::new(stream)
    }
}
