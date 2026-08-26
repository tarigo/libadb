# libadb

[![CI](https://github.com/tarigo/libadb/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tarigo/libadb/actions/workflows/ci.yml)
[![покрытие](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/tarigo/libadb/badge-data/coverage.json)](https://github.com/tarigo/libadb/actions/workflows/ci.yml)

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
| `smol`  | Транспорт поверх `smol::net::TcpStream`; сочетается с `tokio`           |
| `nusb`  | USB-транспорт на базе `nusb` (чистый Rust); сочетается с `rusb`         |
| `rusb`  | USB-транспорт на базе `rusb` (libusb); сочетается с `nusb`              |
| `usb`   | Удобный алиас — включает USB-бэкенд по умолчанию (`nusb`)               |
| `split` | Полнодуплексная пара `Reader`/`Writer` без встроенного рантайма (подтягивает `std`); включается всеми фичами выше |

Фичи аддитивны: собирается любая комбинация. Какой рантайм открывает
сокет и какой бэкенд — USB-устройство, задаётся типами-параметрами
(`transport::runtime::Runtime`, `transport::UsbBackend`), а не фичами,
поэтому соседний крейт, включивший `smol` или `rusb`, не подменит
ничего вашему коду. Чтобы использовать libusb, отключите дефолты и
включите `rusb` напрямую:

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
tcp.set_nodelay(true)?; // ADB болтлив: Нейгл стоит round-trip на каждый обмен
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

## Версия протокола

Библиотека предлагает `0x0100_0001` в своём CNXN и затем принимает
`min(своя, устройства)`; результат доступен через
`Connection::protocol_version()`. Ровно с этой версии ADB отказался от
контрольных сумм полезной нагрузки, поэтому дальше исходящие пакеты
уходят с нулевым `data_check` — так же поступает и сам `adb`.

Два намеренных исключения сохраняют совместимость со старыми
устройствами: пакеты хендшейка (CNXN, AUTH) по-прежнему считаются с
суммой, поскольку версия устройства ещё неизвестна, а входящий
ненулевой `data_check` всегда проверяется. Устройство, сообщившее
`0x0100_0000`, получает трафик с контрольными суммами целиком.

Подсчёт суммы — полный проход по каждой полезной нагрузке. На
микроконтроллере он и составляет основную стоимость записи в канал:
отказ от суммы ускорил `write_stdin` на 32 КиБ примерно вчетверо.

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

## Ограничения

- `OPEN` со стороны устройства принимается через явную очередь:
  `accept_incoming()` отдаёт каждый запрос на вердикт (READY при
  согласии, CLSE при отказе; переполненная очередь отказывает сразу).
  Не хватает пока сервиса правил `reverse:` — установки и листинга
  обратных пробросов с этой стороны; он следующий на очереди.
- При согласованном delayed ack пакет `OKAY` обязан нести 4-байтовый
  кредит, как всегда делает adbd из AOSP; операция, получившая OKAY
  без кредита, завершается ошибкой `ShortReadyPayload`, а не
  угадыванием бюджета.
- Безопасной отмены USB-чтения посреди передачи нет ни у одного
  бэкенда: `select` срабатывает между чтениями (см.
  `ReadCancelSafety`), а прерванное чтение жертвует соединением.
  `rusb` блокирует поток, на котором идёт передача, — поток пула
  рантайма либо самого вызывающего на `Inline` и на `Tokio` вне
  активного Tokio-рантайма, — пока устройство не ответит или не
  отвалится; `nusb` ждёт, не занимая поток ОС.

Сквозные примеры — в [`libadb/examples/`](libadb/examples/)
(`cargo run -p libadb --example shell_v2 -- 127.0.0.1:5555 …`).

## Транспорты

- `TokioTcp` — обёртка над `tokio::net::TcpStream`
- `SmolTcp` — обёртка над `smol::net::TcpStream`
- `transport::nusb::UsbTransport` / `transport::rusb::UsbTransport` —
  USB-транспорты с поиском устройства по VID:PID или серийнику, по
  одному на бэкенд. Оба реализуют `embedded_io_async::{Read, Write}` +
  `libadb::Splittable` и открываются одной точкой входа
  `connect::<Runtime, Backend>("usb://…")` (энумерация вынесена в blocking-пул
  рантайма, чтобы не блокировать executor). Отличаются компромиссами —
  чисто-Rust `nusb` делает асинхронные bulk-передачи через собственный
  IO-бэкенд, `rusb`/libusb оборачивает блокирующие — и enum'ами ошибок
  (`UsbError`, `UsbConnectError` содержат разные варианты и оборачивают
  разные нижележащие типы), поэтому смена бэкенда затрагивает код,
  который называет эти типы.
- Любой тип, реализующий `embedded_io_async::{Read, Write}` +
  `libadb::Splittable`, работает как свой транспорт

Рантайм и бэкенд выбираются в месте вызова, поэтому в сборке могут
жить сразу все:

```rust,ignore
use libadb::transport::{any, common::NoUsb, nusb::Nusb, rusb::Rusb};
use libadb::transport::runtime::{Smol, Tokio};

let a = any::connect::<Tokio, Nusb>("usb://18d1:4ee7").await?;
let b = any::connect::<Smol, Rusb>("usb://serial/ABC123").await?;

// `NoUsb` — это выбор, а не свойство сборки: оба бэкенда выше
// скомпилированы, и вызов всё равно падает в рантайме, потому что
// запрошен ни один из них.
let Err(err) = any::connect::<Tokio, NoUsb>("usb://").await else {
    unreachable!("NoUsb не может обслужить usb://")
};
// tcp:// работает независимо от параметра бэкенда.
let tcp = any::connect::<Tokio, NoUsb>("tcp://127.0.0.1:5555").await?;
```

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

## Разработка

Задачи собраны в [`justfile`](justfile); CI гоняет те же рецепты,
поэтому зелёный `just ci` локально означает те же команды и наборы
фич, что и в workflow.

```sh
just                      # список рецептов
just ci                   # fmt, clippy, тесты, доки, MSRV, no_std, all-features
just clippy-one tokio,smol   # одна конфигурация
just doc                  # доки по узким комбинациям фич
just ffi-example          # сборка C-примера поверх cdylib
just fuzz packet_decode 60
```

## Лицензия

MIT License.
