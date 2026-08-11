# libadb

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
| `smol`  | `smol::net::TcpStream` transport; mutually exclusive with `tokio`       |
| `nusb`  | USB transport via `nusb` (pure-Rust); mutually exclusive with `rusb`    |
| `rusb`  | USB transport via `rusb` (libusb); mutually exclusive with `nusb`       |
| `usb`   | Convenience alias — enables the default USB backend (`nusb`)            |
| `split` | Full-duplex `Reader`/`Writer` pair with no bundled runtime (pulls in `std`); implied by every feature above |

`tokio` and `smol` cannot be enabled together; neither can `nusb` and
`rusb`. To pick the libusb backend, disable defaults and enable `rusb`
directly:

```toml
libadb = { version = "0.1", default-features = false, features = ["tokio", "rusb"] }
```

The core crate is `no_std + alloc`; any runtime feature pulls in `std`.

## Quick start

```toml
[dependencies]
libadb = { version = "0.1", features = ["tokio"] }
```

One-shot command over `shell::v2`:

```rust,ignore
use libadb::shell::v2;
use libadb::{Connection, Feature, TokioTcp};

let tcp = tokio::net::TcpStream::connect("127.0.0.1:5555").await?;
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

See the [`libadb/examples/`](libadb/examples/) directory for end-to-end
programs (`cargo run -p libadb --example shell_v2 -- 127.0.0.1:5555 …`).

## Transports

- `TokioTcp` — wraps `tokio::net::TcpStream`
- `SmolTcp` — wraps `smol::net::TcpStream`
- `UsbTransport` — USB transport with device discovery by VID:PID or
  serial. Two backends with different trade-offs: pure-Rust `nusb`
  (default, async bulk transfers via its own IO backend) or `rusb`/libusb
  (blocking bulk transfers wrapped in `spawn_blocking` / `unblock`).
  What stays the same regardless of backend: the `UsbTransport` type
  name with `embedded_io_async::{Read, Write}` + `libadb::Splittable`
  impls, and the `connect("usb://…")` URI entry point (enumeration is
  offloaded to the runtime's blocking pool so it never stalls the
  executor). What differs: the backend-specific error enums
  (`UsbError`, `UsbConnectError` have different variants and wrap
  different underlying types) and low-level constructors — switching
  backends can therefore be a breaking change for code that touches
  those APIs directly.
- Any type implementing `embedded_io_async::{Read, Write}` +
  `libadb::Splittable` works as a custom transport

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

## License

MIT License.
