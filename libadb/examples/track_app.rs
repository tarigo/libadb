//! Example: stream debuggable/profileable process snapshots.
//!
//! ```text
//! cargo run --example track_app --features tokio -- 127.0.0.1:5555
//! cargo run --example track_app --no-default-features --features smol -- 127.0.0.1:5555
//! ```
//!
//! Requires `~/.android/adbkey` and `~/.android/adbkey.pub`.

#[cfg(not(any(feature = "tokio", feature = "smol")))]
compile_error!("this example requires --features tokio or --features smol");

use std::{env, process};

use libadb::{track_app, Connection, Error, Feature};

#[path = "common/adb_key_auth.rs"]
mod adb_key_auth;
use adb_key_auth::AdbKeyAuth;
async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let auth = AdbKeyAuth::load()?;

    #[cfg(feature = "tokio")]
    let transport = libadb::TokioTcp::new(tokio::net::TcpStream::connect(addr).await?);
    #[cfg(feature = "smol")]
    let transport = libadb::SmolTcp::new(smol::net::TcpStream::connect(addr).await?);

    eprintln!("[*] connecting to {addr} ...");
    let mut conn =
        Connection::<_>::connect(transport, auth, &[Feature::TrackApp, Feature::AppInfo])
            .await
            .map_err(|e| format!("connect: {e}"))?;

    eprintln!("[*] connected, device: {:?}", conn.device_banner());

    let mut rx = [0u8; 64 * 1024];
    let mut tracker = track_app::open(&mut conn, &mut rx)
        .await
        .map_err(|e| format!("open: {e}"))?;

    eprintln!("[*] streaming process snapshots (Ctrl-C to stop) ...");

    loop {
        match tracker.read_snapshot().await {
            Ok(procs) => {
                println!("--- snapshot ({} processes) ---", procs.len());
                for p in &procs {
                    println!(
                        "  pid={:<6} uid={:<6} dbg={} prof={} arch={:<8} name={} pkgs={:?}",
                        p.pid,
                        p.uid.unwrap_or(-1),
                        if p.debuggable { "Y" } else { "N" },
                        if p.profileable { "Y" } else { "N" },
                        p.architecture,
                        p.process_name.as_deref().unwrap_or("?"),
                        p.package_names,
                    );
                }
            }
            Err(Error::ChannelClosed) => {
                eprintln!("[*] channel closed");
                break;
            }
            Err(e) => return Err(format!("read: {e}").into()),
        }
    }

    Ok(())
}

async fn async_main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <host:port>", args[0]);
        process::exit(2);
    }

    if let Err(e) = run(&args[1]).await {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() {
    async_main().await;
}

#[cfg(feature = "smol")]
fn main() {
    smol::block_on(async_main());
}
