//! Example: reverse forward — the device listens, the host serves.
//!
//! ```text
//! # Terminal 1: something to serve on the host
//! python3 -m http.server 8899
//!
//! # Terminal 2: the bridge (device listens on tcp:6100)
//! cargo run --example reverse --features tokio -- 192.168.2.106:5555 tcp:6100 8899
//!
//! # On the device: adbd binds IPv6-first, so talk to ::1 — and keep
//! # stdin open until the reply arrives (nc closes on stdin EOF, and a
//! # connection closed before the bridge answers READY is dropped by
//! # adbd wholesale, buffered bytes included):
//! adb shell '(printf "GET / HTTP/1.0\r\n\r\n"; sleep 5) | nc ::1 6100'
//! ```
//!
//! Serves one connection at a time: each device-initiated channel is
//! bridged to `127.0.0.1:<local-port>` until either side closes, then
//! the next one is accepted. Channels opened for destinations other
//! than the established rule are rejected.
//!
//! Requires `~/.android/adbkey{,.pub}` (see `adb keygen`).

#[path = "common/adb_key_auth.rs"]
mod adb_key_auth;

use libadb::channel::SelectResult;
use libadb::{Connection, Error, TokioTcp};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(addr), Some(device_spec), Some(local_port)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: reverse ADDR DEVICE_SPEC LOCAL_PORT");
        eprintln!("       reverse 127.0.0.1:5555 tcp:6100 8899");
        std::process::exit(2);
    };
    let local_port: u16 = local_port.parse()?;

    let tcp = tokio::net::TcpStream::connect(&addr).await?;
    tcp.set_nodelay(true)?;
    let auth = adb_key_auth::AdbKeyAuth::load()?;
    let mut conn = Connection::<_>::connect(TokioTcp::new(tcp), auth, &[]).await?;

    let host_spec = format!("tcp:{local_port}");
    let assigned = libadb::reverse::establish(&mut conn, &device_spec, &host_spec).await?;
    if assigned.is_empty() {
        println!("[*] rule established: {device_spec} -> 127.0.0.1:{local_port}");
    } else {
        println!(
            "[*] rule established: device port {} -> 127.0.0.1:{local_port}",
            String::from_utf8_lossy(&assigned)
        );
    }

    // The rule's OPENs carry the host spec as their NUL-terminated
    // destination; anything else on this connection is not ours.
    let mut expected_dest = host_spec.into_bytes();
    expected_dest.push(0);

    loop {
        let incoming = conn.accept_incoming().await?;
        let dest = incoming.destination().to_vec();
        println!("[*] incoming: {:?}", String::from_utf8_lossy(&dest));
        if dest != expected_dest {
            eprintln!("[!] unexpected destination, rejecting");
            incoming.reject().await?;
            continue;
        }
        let ch = incoming.accept().await?;

        let local = match tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await {
            Ok(s) => {
                s.set_nodelay(true)?;
                s
            }
            Err(e) => {
                eprintln!("[!] 127.0.0.1:{local_port}: {e}");
                conn.close_channel(ch).await?;
                continue;
            }
        };
        let (mut local_r, mut local_w) = local.into_split();

        let mut chan_buf = vec![0u8; 16 * 1024];
        let mut sock_buf = vec![0u8; 16 * 1024];
        loop {
            // Anything that ends only this bridge — either side closing,
            // a local socket error — answers `true`; connection-level
            // failures propagate and stop the service.
            let done = match conn
                .select_channel(ch, &mut chan_buf, local_r.read(&mut sock_buf))
                .await
            {
                Ok(SelectResult::Data(n)) => match local_w.write_all(&chan_buf[..n]).await {
                    Ok(()) => false,
                    Err(e) => {
                        eprintln!("[!] local write: {e}");
                        true
                    }
                },
                // The local side is done: close our half and move on.
                Ok(SelectResult::Interrupted(Ok(0))) => true,
                Ok(SelectResult::Interrupted(Ok(n))) => {
                    match conn.write_channel(ch, &sock_buf[..n]).await {
                        Ok(()) => false,
                        // The device closed while we waited for credit.
                        Err(Error::ChannelClosed) => true,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(SelectResult::Interrupted(Err(e))) => {
                    eprintln!("[!] local read: {e}");
                    true
                }
                Err(Error::ChannelClosed) => true,
                Err(e) => return Err(e.into()),
            };
            if done {
                // Frees the slot — required even after a remote CLSE,
                // which only marks it. A failure here is the transport
                // dying, not a per-bridge event: propagate it rather
                // than looping on a dead connection.
                conn.close_channel(ch).await?;
                break;
            }
        }
        println!("[*] bridge closed");
    }
}
