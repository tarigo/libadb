//! Example: `adb pair` — teach a device the host key.
//!
//! ```text
//! cargo run --example pair --features tokio,pairing,host-keys -- 192.168.1.5:37421 592781
//! ```
//!
//! Turn on "Wireless debugging" on the device, then "Pair device with
//! pairing code". The address and the six digits are both on that
//! screen. Neither survives: the port changes every time and the
//! pairing server stops as soon as one host gets through.
//!
//! Afterwards the device accepts `~/.android/adbkey` on its *connect*
//! port, which is a different number on the same screen. That is what
//! `shell_v2 --features tls` wants.
//!
//! A key the device already trusts, one confirmed at a USB prompt,
//! needs none of this.

#[cfg(not(any(feature = "tokio", feature = "smol")))]
compile_error!("this example requires --features tokio,pairing,host-keys");

use std::{env, process};

use libadb::keys::rsa::rand_core::OsRng;
use libadb::pairing::pair;
use libadb::tls::{TlsClientConfig, TlsIdentity};
use libadb::transport::tls::MaybeTls;

#[cfg(feature = "tokio")]
type Rt = libadb::transport::runtime::Tokio;
#[cfg(all(feature = "smol", not(feature = "tokio")))]
type Rt = libadb::transport::runtime::Smol;

#[path = "common/adb_key_auth.rs"]
mod adb_key_auth;

async fn run(target: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or("expected HOST:PORT, e.g. 192.168.1.5:37421")?;
    let port: u16 = port.parse().map_err(|_| "port is not a number")?;
    // Here and not in the library, which also pairs with the password
    // from a QR code. A typo caught now never reaches the device, which
    // would count it against its twenty attempts.
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the pairing code is six digits".into());
    }

    let key = adb_key_auth::load_or_generate()?;
    // The same certificate a session later presents.
    let identity = TlsIdentity::from_key(&key, &mut OsRng)?;
    let tls = TlsClientConfig::adb(&identity)?;

    eprintln!("[*] pairing with {host}:{port} ...");
    let socket = <Rt as libadb::transport::runtime::Runtime>::connect_tcp(host, port).await?;
    let mut transport = MaybeTls::plain(socket);

    let paired = pair(&mut transport, &tls, &key, code, &mut OsRng).await?;

    eprintln!("[*] paired. device guid: {}", paired.guid);
    eprintln!("[*] it now accepts this key on its wireless-debugging port");
    Ok(())
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} HOST:PORT CODE", args[0]);
        eprintln!("  both are on the device's \"Pair device with pairing code\" screen");
        process::exit(2);
    }

    #[cfg(feature = "tokio")]
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(&args[1], &args[2]));
    #[cfg(all(feature = "smol", not(feature = "tokio")))]
    let result = smol::block_on(run(&args[1], &args[2]));

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
