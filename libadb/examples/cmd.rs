//! Example: run `cmd` commands with automatic transport selection.
//!
//! ```text
//! # One-shot (list packages):
//! cargo run --example cmd --features tokio -- 127.0.0.1:5555 package list packages
//! cargo run --example cmd --no-default-features --features smol -- 127.0.0.1:5555 package list packages
//!
//! # Streaming (monitor activity starts):
//! cargo run --example cmd --features tokio -- 127.0.0.1:5555 -s activity monitor
//! ```
//!
//! Automatically picks `abb_exec`/`abb` when available, falls back to
//! `shell,v2,raw:cmd …` on older devices.
//!
//! Requires `~/.android/adbkey` and `~/.android/adbkey.pub`.

#[cfg(not(any(feature = "tokio", feature = "smol")))]
compile_error!("this example requires --features tokio or --features smol");

use std::io::{self, Write};
use std::{env, process};

use libadb::shell::v2::Frame;
use libadb::{cmd, Connection, Error, Feature};

#[path = "common/adb_key_auth.rs"]
mod adb_key_auth;
use adb_key_auth::AdbKeyAuth;
async fn run_exec(addr: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let auth = AdbKeyAuth::load()?;

    #[cfg(feature = "tokio")]
    let transport = libadb::TokioTcp::new(tokio::net::TcpStream::connect(addr).await?);
    #[cfg(feature = "smol")]
    let transport = libadb::SmolTcp::new(smol::net::TcpStream::connect(addr).await?);

    eprintln!("[*] connecting to {addr} ...");
    let mut conn = Connection::<_>::connect(
        transport,
        auth,
        &[Feature::ShellV2, Feature::AbbExec, Feature::Abb],
    )
    .await
    .map_err(|e| format!("connect: {e}"))?;

    eprintln!("[*] connected, device: {:?}", conn.device_banner());

    let mut rx = [0u8; 64 * 1024];
    let output = cmd::exec(&mut conn, args, &mut rx)
        .await
        .map_err(|e| format!("cmd exec: {e}"))?;

    io::stdout().write_all(&output)?;
    io::stdout().flush()?;

    Ok(())
}

async fn run_stream(addr: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let auth = AdbKeyAuth::load()?;

    #[cfg(feature = "tokio")]
    let transport = libadb::TokioTcp::new(tokio::net::TcpStream::connect(addr).await?);
    #[cfg(feature = "smol")]
    let transport = libadb::SmolTcp::new(smol::net::TcpStream::connect(addr).await?);

    eprintln!("[*] connecting to {addr} ...");
    let mut conn = Connection::<_>::connect(
        transport,
        auth,
        &[Feature::ShellV2, Feature::AbbExec, Feature::Abb],
    )
    .await
    .map_err(|e| format!("connect: {e}"))?;

    eprintln!("[*] connected, device: {:?}", conn.device_banner());

    let mut rx = [0u8; 64 * 1024];
    let mut session = cmd::open(&mut conn, args, &mut rx)
        .await
        .map_err(|e| format!("cmd open: {e}"))?;

    eprintln!("[*] streaming (Ctrl-C to stop) ...");

    let stdout = io::stdout();
    let stderr = io::stderr();

    loop {
        match session.read_frame().await {
            Ok(Frame::Stdout(data)) => {
                let mut out = stdout.lock();
                if let Err(e) = out.write_all(&data).and_then(|_| out.flush()) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(e.into());
                }
            }
            Ok(Frame::Stderr(data)) => {
                let mut err = stderr.lock();
                err.write_all(&data)?;
                err.flush()?;
            }
            Ok(Frame::Exit(code)) => {
                eprintln!("[*] exit code: {code}");
                process::exit(code as i32);
            }
            Ok(Frame::Other { .. }) => {}
            Err(Error::ChannelClosed) => {
                eprintln!("[*] session ended");
                break;
            }
            Err(e) => return Err(format!("read: {e}").into()),
        }
    }

    Ok(())
}

async fn async_main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <host:port> [-s] <service> [args...]", args[0]);
        eprintln!();
        eprintln!("  One-shot:");
        eprintln!("    {} 127.0.0.1:5555 package list packages", args[0]);
        eprintln!();
        eprintln!("  Streaming (-s flag):");
        eprintln!("    {} 127.0.0.1:5555 -s activity monitor", args[0]);
        process::exit(2);
    }

    let addr = &args[1];
    let streaming = args[2] == "-s";
    let cmd_args: Vec<&str> = if streaming {
        args[3..].iter().map(|s| s.as_str()).collect()
    } else {
        args[2..].iter().map(|s| s.as_str()).collect()
    };

    if cmd_args.is_empty() {
        eprintln!("error: no service/command arguments provided");
        process::exit(2);
    }

    let result = if streaming {
        run_stream(addr, &cmd_args).await
    } else {
        run_exec(addr, &cmd_args).await
    };

    if let Err(e) = result {
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
