//! Example: forward — the host listens, the device serves.
//!
//! ```text
//! # On the device: something to serve
//! adb shell 'echo served-by-device | nc -l -p 7788'
//!
//! # The bridge (host listens on 127.0.0.1:9911)
//! cargo run --example forward --features tokio -- 192.168.2.106:5555 9911 tcp:7788
//!
//! # Anywhere on the host:
//! nc 127.0.0.1 9911
//! ```
//!
//! No reverse rule is needed for this direction: every accepted local
//! connection simply opens a channel whose destination is the remote
//! spec, and adbd connects it on the device. Serves one connection at
//! a time.
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
    let (Some(addr), Some(local_port), Some(remote_spec)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: forward ADDR LOCAL_PORT REMOTE_SPEC");
        eprintln!("       forward 127.0.0.1:5555 9911 tcp:7788");
        std::process::exit(2);
    };
    let local_port: u16 = local_port.parse()?;

    let tcp = tokio::net::TcpStream::connect(&addr).await?;
    tcp.set_nodelay(true)?;
    let auth = adb_key_auth::AdbKeyAuth::load()?;
    let mut conn = Connection::<_>::connect(TokioTcp::new(tcp), auth, &[]).await?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
    println!("[*] listening on 127.0.0.1:{local_port} -> {remote_spec}");

    let mut dest = remote_spec.clone().into_bytes();
    dest.push(0);

    loop {
        let (local, peer) = listener.accept().await?;
        local.set_nodelay(true)?;
        println!("[*] {peer} connected");

        let ch = match conn.open_channel(&dest).await {
            // The device refusing this destination ends one bridge;
            // anything else — a dead transport, a protocol fault — is
            // the whole forwarder's problem, so it propagates instead
            // of silently dropping every future local connection.
            Ok(ch) => ch,
            Err(Error::ChannelClosed) => {
                eprintln!("[!] open {remote_spec}: refused by the device");
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let (mut local_r, mut local_w) = local.into_split();

        let mut chan_buf = vec![0u8; 16 * 1024];
        let mut sock_buf = vec![0u8; 16 * 1024];
        loop {
            // Anything that ends only this bridge — either side closing,
            // a local socket error — answers `true`; connection-level
            // failures propagate and stop the forwarder.
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
