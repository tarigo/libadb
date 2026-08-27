# libadb

[![CI](https://github.com/tarigo/libadb/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tarigo/libadb/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/tarigo/libadb/badge-data/coverage.json)](https://github.com/tarigo/libadb/actions/workflows/ci.yml)

Low-level ADB (Android Debug Bridge) wire-protocol library for Rust.

Talks to a device directly over TCP or USB — no `adbd` fork/exec, no
`adb` binary, no platform-tools dependency. `no_std + alloc` core with
optional async runtimes; a separate `libadb-ffi` crate exposes a C ABI.

**Status:** pre-1.0 — the public API may change in semver-breaking ways before 1.0.

English · [Русский](README.ru.md)

## Workspace

This repository is a Cargo workspace with two published crates:

| Crate        | Type                          | Purpose                                |
|--------------|-------------------------------|----------------------------------------|
| `libadb`     | `rlib`                        | `no_std + alloc` core protocol library |
| `libadb-ffi` | `cdylib` / `staticlib` / `rlib` | C ABI on top of `libadb`               |

`libadb` itself is rlib-only, so a pure `no_std + alloc` consumer never
drags in `cdylib` / `staticlib` linkage requirements (allocator, panic
handler). The `libadb-ffi` crate is where those live.

## Feature flags (`libadb`)

| Flag    | What it enables                                                         |
|---------|-------------------------------------------------------------------------|
| `tokio` | `tokio::net::TcpStream` transport (default)                             |
| `smol`  | `smol::net::TcpStream` transport; combinable with `tokio`               |
| `nusb`  | USB transport via `nusb` (pure-Rust); combinable with `rusb`            |
| `rusb`  | USB transport via `rusb` (libusb); combinable with `nusb`               |
| `usb`   | Convenience alias — enables the default USB backend (`nusb`)            |
| `split` | Full-duplex `Reader`/`Writer` pair with no bundled runtime (pulls in `std`); implied by every feature above |

Features are additive: any combination compiles. Which runtime dials a
socket and which backend opens a USB device are type arguments
(`transport::runtime::Runtime`, `transport::UsbBackend`), not features,
so an unrelated crate enabling `smol` or `rusb` cannot change what your
code talks to. To use the libusb backend, disable defaults and enable
`rusb` directly:

```toml
libadb = { version = "0.3", default-features = false, features = ["tokio", "rusb"] }
```

The core crate is `no_std + alloc`; any runtime feature pulls in `std`.

## Quick start

```toml
[dependencies]
libadb = { version = "0.3", features = ["tokio"] }
```

One-shot command over `shell::v2`:

```rust,ignore
use libadb::shell::v2;
use libadb::{Connection, Feature, TokioTcp};

let tcp = tokio::net::TcpStream::connect("127.0.0.1:5555").await?;
tcp.set_nodelay(true)?; // ADB is chatty; Nagle costs a round per exchange
let transport = TokioTcp::new(tcp);

let mut conn = Connection::<_>::connect(
    transport,
    auth, // your `libadb::auth::Authenticator` impl
    &[Feature::ShellV2],
).await?;

let mut rx = [0u8; 64 * 1024];
let out = v2::exec(&mut conn, "getprop ro.product.model", &mut rx).await?;
println!("{}", core::str::from_utf8(&out.stdout)?);
```

`Authenticator` is a user-supplied trait — typically an RSA signer
reading `~/.android/adbkey`. See any file under `libadb/examples/` for
a complete `AdbKeyAuth` that uses the `rsa` crate.

## Memory budget

`ConnectionConfig` bounds everything the library allocates per
connection:

| Field                | Default (`new()`) | `embedded()` | Effect                                              |
|----------------------|-------------------|--------------|-----------------------------------------------------|
| `max_payload`        | 1 MiB             | 8 KiB        | advertised in CNXN — caps any single inbound packet |
| `initial_ack_bytes`  | 32 MiB            | 32 KiB       | delayed-ACK credit granted per channel              |
| `max_rx_per_channel` | unbounded         | 64 KiB       | fuse on data buffered for an unread channel         |

```rust,ignore
use libadb::{Connection, ConnectionConfig, Feature};

let conn = Connection::<_>::connect_with_config(
    transport, auth, &[Feature::ShellV2], ConnectionConfig::embedded(),
).await?;
```

The default matches what `adb` does on a desktop. On a microcontroller
it does not fit: a device that takes the advertised 1 MiB at face value
can send a packet the receive buffer has to hold whole, and with only a
few hundred KiB of RAM a single 64 KiB WRTE is already enough to
exhaust the heap. Since adbd never exceeds the size the host
advertised, `embedded()` (or `new().with_max_payload(…)`) is what keeps
the footprint bounded.

## Protocol version

The library offers `0x0100_0001` in its CNXN and then adopts
`min(mine, the device's)`, readable via `Connection::protocol_version()`.
ADB retired payload checksums at exactly that version, so from there on
outgoing packets leave `data_check` zero — the same thing `adb` does.

Two deliberate exceptions keep older peers working: handshake packets
(CNXN, AUTH) are still checksummed, because the device has not announced
its version yet, and an inbound non-zero `data_check` is always verified.
A device reporting `0x0100_0000` gets checksummed traffic throughout.

The sum is a full pass over every payload. On a microcontroller that
dominates the cost of a channel write: skipping it made a 32 KiB
`write_stdin` roughly four times faster.

## Supported services

| Module        | Wire service                 | Notes                             |
|---------------|------------------------------|-----------------------------------|
| `shell::v1`   | `shell:`                     | Interleaved stdout/stderr, no exit code |
| `shell::v2`   | `shell,v2,…:`                | Framed stdout/stderr/exit, PTY + window-size |
| `exec`        | `exec:`                      | Binary-clean stdout, no PTY, no exit code |
| `cmd`         | `abb_exec`/`abb`/`shell:cmd` | Auto-selects the best available service |
| `abb`         | `abb_exec:`, `abb:`          | Android 10+ Binder Bridge         |
| `logcat`      | `shell,v2,raw:logcat -B …`   | Binary logcat entries, parsed     |
| `sync`        | `sync:`                      | `STAT`/`LIST`/`SEND`/`RECV`, v1 + v2 |
| `track_app`   | `track-app:`                 | Streaming debuggable-process snapshots |
| `reverse`     | `reverse:…`                  | Reverse-forward rules; incoming channels via `accept_incoming` |

See the [`libadb/examples/`](libadb/examples/) directory for end-to-end
programs (`cargo run -p libadb --example shell_v2 -- 127.0.0.1:5555 …`).

## Limitations

- With delayed ack negotiated, an `OKAY` must carry its 4-byte credit,
  as AOSP's adbd always does; the operation that received a creditless
  one fails with `ShortReadyPayload` rather than having a budget
  guessed for it.
- USB reads cannot be cancelled safely mid-transfer on either backend:
  `select` takes effect between reads (see `ReadCancelSafety`), and
  aborting an in-flight read forfeits the connection. The `rusb`
  backend blocks the thread the transfer runs on — a runtime pool
  thread, or the caller itself under the `Inline` runtime and under
  `Tokio` outside an active Tokio runtime — until the device answers
  or detaches; `nusb` waits without parking an OS thread.

## Transports

- `TokioTcp` — wraps `tokio::net::TcpStream`
- `SmolTcp` — wraps `smol::net::TcpStream`
- `transport::nusb::UsbTransport` / `transport::rusb::UsbTransport` —
  USB transports with device discovery by VID:PID or serial, one per
  backend. Both implement `embedded_io_async::{Read, Write}` +
  `libadb::Splittable` and are reached through the same
  `connect::<Runtime, Backend>("usb://…")` entry point (enumeration is offloaded
  to the runtime's blocking pool so it never stalls the executor). They
  differ in trade-offs — pure-Rust `nusb` does async bulk transfers via
  its own IO backend, `rusb`/libusb wraps blocking ones — and in their
  error enums (`UsbError`, `UsbConnectError` have different variants and
  wrap different underlying types), so switching backends touches any
  code that names those types.
- Any type implementing `embedded_io_async::{Read, Write}` +
  `libadb::Splittable` works as a custom transport

Runtime and backend are chosen per call site, so a build may carry all
of them at once:

```rust,ignore
use libadb::transport::{any, common::NoUsb, nusb::Nusb, rusb::Rusb};
use libadb::transport::runtime::{Smol, Tokio};

let a = any::connect::<Tokio, Nusb>("usb://18d1:4ee7").await?;
let b = any::connect::<Smol, Rusb>("usb://serial/ABC123").await?;

// `NoUsb` is a choice, not a statement about the build: both
// backends above are compiled in, and this call still fails at
// runtime because it asked for neither.
let Err(err) = any::connect::<Tokio, NoUsb>("usb://").await else {
    unreachable!("NoUsb cannot serve usb://")
};
// tcp:// works regardless of the backend parameter.
let tcp = any::connect::<Tokio, NoUsb>("tcp://127.0.0.1:5555").await?;
```

`Connection::split()` gives you a full-duplex `Reader` / `Writer` pair
so that a reader task and a writer task can coexist on the same
connection without locking each other out.

## C ABI (`libadb-ffi`)

`libadb-ffi` is a thin `cdylib` / `staticlib` wrapper over `libadb` with
no async runtime of its own — a tiny internal executor drives the async
transport so callers see a fully blocking API. The header lives at
[`libadb-ffi/include/libadb.h`](libadb-ffi/include/libadb.h) and covers:

- connection lifecycle and handshake
- caller-supplied authenticators (`adb_connect_with_authenticator`) —
  for private keys living outside the process (HSM, remote signer)
- channel open/read/write/close
- `shell_v2` session with framing, stdin, PTY resize
- structured feature queries (`adb_connection_has_feature`,
  `adb_feature_name`, `adb_connection_features`)

Build (no async runtime is linked; add `--features usb` or
`--features rusb` for USB transport support):

```sh
cargo build -p libadb-ffi
cc -I libadb-ffi/include -o ffi_shell libadb-ffi/examples/ffi_shell.c \
   -L target/debug -ladb -lpthread -ldl -lm
```

A full interactive-shell C client is in
[`libadb-ffi/examples/ffi_shell.c`](libadb-ffi/examples/ffi_shell.c).

## Layout

```
libadb/                    # core protocol library (rlib, no_std + alloc)
  src/base/                wire protocol, channels, banner, auth trait
  src/transport/           TCP (tokio/smol) and USB (nusb or rusb) transports
  src/shell/v{1,2}.rs      shell services
  src/{exec,cmd,abb}.rs    exec / cmd-fallback / Android Binder Bridge
  src/{logcat,sync}.rs     logcat stream and file-sync protocol
  src/track_app.rs         track-app snapshots
  src/split.rs             full-duplex Reader/Writer pair
  tests/                   integration tests via fake_device fixture
  examples/                Rust examples per service
libadb-ffi/                # C ABI (cdylib + staticlib + rlib)
  src/                     C entry points + RSA Authenticator
  include/libadb.h         C header
  examples/ffi_shell.c     interactive shell client in C
fuzz/                      cargo-fuzz targets (excluded from workspace)
```

## Development

Tasks live in a [`justfile`](justfile); CI drives the same recipes, so a
green `just ci` locally means the same commands and feature sets the
workflow runs.

```sh
just                      # list recipes
just ci                   # fmt, clippy, tests, docs, MSRV, no_std, all-features
just clippy-one tokio,smol   # one configuration
just doc                  # docs per narrow feature combination
just ffi-example          # build the C example against the cdylib
just fuzz packet_decode 60
```

## License

MIT License.
