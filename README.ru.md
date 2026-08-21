# libadb

Низкоуровневая библиотека проводного протокола ADB (Android Debug Bridge)
для Rust.

Общается с устройством напрямую по TCP или USB — без форка `adbd`, без
бинарника `adb` и без зависимости от platform-tools. Ядро
`no_std + alloc`, опциональные async-рантаймы; отдельный крейт
`libadb-ffi` предоставляет C ABI.

**Статус:** pre-1.0 — публичный API может меняться несовместимо вплоть до релиза 1.0.

[English](README.md) · Русский

## Воркспейс

Репозиторий — Cargo-воркспейс с двумя публикуемыми крейтами:

| Крейт        | Тип                             | Назначение                              |
|--------------|---------------------------------|-----------------------------------------|
| `libadb`     | `rlib`                          | Ядро протокола, `no_std + alloc`        |
| `libadb-ffi` | `cdylib` / `staticlib` / `rlib` | C ABI поверх `libadb`                   |

`libadb` собирается только как `rlib`, поэтому потребитель в режиме
`no_std + alloc` не тащит требования линковки `cdylib` / `staticlib`
(глобальный аллокатор, panic handler). Эти требования живут в
`libadb-ffi`.

## Feature-флаги (`libadb`)

| Флаг    | Что включает                                                            |
|---------|-------------------------------------------------------------------------|
| `tokio` | Транспорт поверх `tokio::net::TcpStream` (по умолчанию)                 |
| `smol`  | Транспорт поверх `smol::net::TcpStream`; взаимоисключающий с `tokio`    |
| `nusb`  | USB-транспорт на базе `nusb` (чистый Rust); взаимоисключающий с `rusb`  |
| `rusb`  | USB-транспорт на базе `rusb` (libusb); взаимоисключающий с `nusb`       |
| `usb`   | Удобный алиас — включает USB-бэкенд по умолчанию (`nusb`)               |
| `split` | Полнодуплексная пара `Reader`/`Writer` без встроенного рантайма (подтягивает `std`); включается всеми фичами выше |

`tokio` и `smol` нельзя включать одновременно; то же и для `nusb` с
`rusb`. Чтобы выбрать libusb-бэкенд, отключите дефолты и включите `rusb`
напрямую:

```toml
libadb = { version = "0.1", default-features = false, features = ["tokio", "rusb"] }
```

Ядро крейта — `no_std + alloc`; любая рантайм-фича подтягивает `std`.

## Быстрый старт

```toml
[dependencies]
libadb = { version = "0.1", features = ["tokio"] }
```

Разовая команда через `shell::v2`:

```rust,ignore
use libadb::shell::v2;
use libadb::{Connection, Feature, TokioTcp};

let tcp = tokio::net::TcpStream::connect("127.0.0.1:5555").await?;
let transport = TokioTcp::new(tcp);

let mut conn = Connection::<_>::connect(
    transport,
    auth, // ваша реализация `libadb::auth::Authenticator`
    &[Feature::ShellV2],
).await?;

let mut rx = [0u8; 64 * 1024];
let out = v2::exec(&mut conn, "getprop ro.product.model", &mut rx).await?;
println!("{}", core::str::from_utf8(&out.stdout)?);
```

`Authenticator` — пользовательский трейт, обычно RSA-подписыватель,
читающий `~/.android/adbkey`. В любом файле из `libadb/examples/` есть
готовый `AdbKeyAuth` на основе крейта `rsa`.

## Бюджет памяти

`ConnectionConfig` ограничивает всё, что библиотека выделяет на одно
соединение:

| Поле                 | По умолчанию (`new()`) | `embedded()` | На что влияет                                          |
|----------------------|------------------------|--------------|--------------------------------------------------------|
| `max_payload`        | 1 МиБ                  | 8 КиБ        | объявляется в CNXN — потолок одного входящего пакета   |
| `initial_ack_bytes`  | 32 МиБ                 | 32 КиБ       | кредит delayed-ACK, выдаваемый на канал                |
| `max_rx_per_channel` | без лимита             | 64 КиБ       | предохранитель на буферизацию непрочитанного канала    |

```rust,ignore
use libadb::{Connection, ConnectionConfig, Feature};

let conn = Connection::<_>::connect_with_config(
    transport, auth, &[Feature::ShellV2], ConnectionConfig::embedded(),
).await?;
```

Значения по умолчанию повторяют поведение `adb` на десктопе. На
микроконтроллере они не подходят: устройство вправе воспользоваться
объявленным 1 МиБ, а такой пакет приёмнику нужно удержать целиком —
при паре сотен килобайт RAM уже одиночный WRTE в 64 КиБ исчерпывает
память. Поскольку adbd никогда не превышает объявленный хостом размер,
`embedded()` (или `new().with_max_payload(…)`) удерживает расход в
заданных рамках.

## Поддерживаемые сервисы

| Модуль        | Имя на проводе               | Комментарий                       |
|---------------|------------------------------|-----------------------------------|
| `shell::v1`   | `shell:`                     | Смешанные stdout/stderr, без кода выхода |
| `shell::v2`   | `shell,v2,…:`                | Кадры stdout/stderr/exit, PTY и изменение размера окна |
| `exec`        | `exec:`                      | Бинарно-чистый stdout, без PTY и кода выхода |
| `cmd`         | `abb_exec`/`abb`/`shell:cmd` | Автовыбор наиболее подходящего сервиса |
| `abb`         | `abb_exec:`, `abb:`          | Android Binder Bridge (Android 10+) |
| `logcat`      | `shell,v2,raw:logcat -B …`   | Бинарные записи logcat, распарсенные |
| `sync`        | `sync:`                      | `STAT`/`LIST`/`SEND`/`RECV`, v1 и v2 |
| `track_app`   | `track-app:`                 | Стриминг снапшотов debuggable-процессов |

Сквозные примеры — в [`libadb/examples/`](libadb/examples/)
(`cargo run -p libadb --example shell_v2 -- 127.0.0.1:5555 …`).

## Транспорты

- `TokioTcp` — обёртка над `tokio::net::TcpStream`
- `SmolTcp` — обёртка над `smol::net::TcpStream`
- `UsbTransport` — USB-транспорт с поиском устройства по VID:PID или
  серийнику. Два бэкенда с разными компромиссами: чисто-Rust `nusb`
  (по умолчанию, асинхронные bulk-передачи через собственный IO-
  бэкенд) или `rusb`/libusb (блокирующие bulk-передачи, обёрнутые в
  `spawn_blocking` / `unblock`). Что гарантированно одинаково
  независимо от бэкенда: имя типа `UsbTransport` с реализациями
  `embedded_io_async::{Read, Write}` + `libadb::Splittable` и точка
  входа `connect("usb://…")` (энумерация вынесена в blocking-пул
  рантайма, чтобы не блокировать executor). Что отличается:
  backend-специфичные enum'ы ошибок (`UsbError`, `UsbConnectError`
  содержат разные варианты и оборачивают разные нижележащие типы)
  и низкоуровневые конструкторы — поэтому переключение бэкенда
  может быть breaking change для кода, напрямую работающего с
  этими API.
- Любой тип, реализующий `embedded_io_async::{Read, Write}` +
  `libadb::Splittable`, работает как свой транспорт

`Connection::split()` возвращает полнодуплексную пару `Reader` /
`Writer` — задача-читатель и задача-писатель могут работать на одном
соединении, не блокируя друг друга.

## C ABI (`libadb-ffi`)

`libadb-ffi` — это тонкая `cdylib`/`staticlib`-обёртка над `libadb` без
собственного async-рантайма (внутри крутится крошечный исполнитель,
прогоняющий async-транспорт), так что снаружи API полностью блокирующий.
Заголовок —
[`libadb-ffi/include/libadb.h`](libadb-ffi/include/libadb.h), в нём:

- жизненный цикл соединения и хендшейк
- пользовательские аутентификаторы (`adb_connect_with_authenticator`) —
  когда приватный ключ живёт вне процесса (HSM, удалённый подписант)
- открытие/чтение/запись/закрытие канала
- сессия `shell_v2` с кадрированием, stdin и ресайзом PTY
- структурированные запросы фичей (`adb_connection_has_feature`,
  `adb_feature_name`, `adb_connection_features`)

Сборка (async-рантайм не линкуется вовсе; для USB-транспорта добавьте
`--features usb` или `--features rusb`):

```sh
cargo build -p libadb-ffi
cc -I libadb-ffi/include -o ffi_shell libadb-ffi/examples/ffi_shell.c \
   -L target/debug -ladb -lpthread -ldl -lm
```

Интерактивный shell-клиент на C целиком — в
[`libadb-ffi/examples/ffi_shell.c`](libadb-ffi/examples/ffi_shell.c).

## Структура

```
libadb/                    # ядро протокола (rlib, no_std + alloc)
  src/base/                протокол, каналы, баннер, трейт аутентификации
  src/transport/           транспорты TCP (tokio/smol) и USB (nusb или rusb)
  src/shell/v{1,2}.rs      shell-сервисы
  src/{exec,cmd,abb}.rs    exec / fallback cmd / Android Binder Bridge
  src/{logcat,sync}.rs     поток logcat и протокол синхронизации файлов
  src/track_app.rs         снапшоты track-app
  src/split.rs             полнодуплексная пара Reader/Writer
  tests/                   интеграционные тесты через фикстуру fake_device
  examples/                Rust-примеры по каждому сервису
libadb-ffi/                # C ABI (cdylib + staticlib + rlib)
  src/                     точки входа C + RSA Authenticator
  include/libadb.h         C-заголовок
  examples/ffi_shell.c     интерактивный shell-клиент на C
fuzz/                      цели cargo-fuzz (вне воркспейса)
```

## Лицензия

MIT License.
