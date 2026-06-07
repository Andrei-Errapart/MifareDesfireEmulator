# Mifare DESFire Emulator

A software emulator of a [Mifare DESFire](https://en.wikipedia.org/wiki/MIFARE#MIFARE_DESFire) smartcard. There is **no NFC hardware involved** — a test client speaks the DESFire protocol over a TCP socket to an emulator process that maintains card state in memory and on disk. This lets you develop and test DESFire reader logic without physical cards or readers.

## Components

| Directory  | Language / toolchain     | Role                                                                                  |
|------------|--------------------------|---------------------------------------------------------------------------------------|
| `mdemu/`   | F#, .NET 8             | The emulator. A TCP server (port `1555`) that behaves like a DESFire card (PICC). All card logic lives in `mdemu.fs`; local protocol framing lives in `MDComm.fs`. |
| `MDComm/`  | Protocol Buffers        | Shared wire-protocol schema. `mdcomm.proto` is used by the C++ client; the F# emulator has a small matching codec. |
| `mdtest/`  | C++, Linux (`Makefile`)  | The test client. Drives the emulator using [libfreefare](https://github.com/nfc-tools/libfreefare) through a fake [libnfc](https://github.com/nfc-tools/libnfc) driver that sends APDUs over TCP instead of to NFC hardware. |

## How it works

```
libfreefare (mdtest.cpp)          writes DESFire test scenarios
  → proxydriver (proxydriver.cpp)  a fake libnfc driver: APDUs go to TCP, not hardware
  → TCP :1555, length-delimited protobuf (MessageToSlave / MessageFromSlave)
  → mdemu (mdemu.fs)
  → MifareDesfire.Transceive       the DESFire command interpreter / card state machine
  → response back up the chain
```

The emulator decodes wrapped ISO-7816 APDUs and implements the DESFire command set: authentication (3-pass mutual auth with 3DES), application and file management, key changes, and encrypted/plain read/write. Card state is persisted per connection as JSON in `card-<uid>.txt`; delete that file to reset a card to its factory state.

## Building and running

### Emulator (`mdemu`) — .NET 8

Build the emulator with the .NET SDK:

```
dotnet build mdemu.sln
```

Run it, optionally passing a 7-byte card UID as hex (defaults to `04345678123456`):

```
dotnet run --project mdemu/mdemu.fsproj -- 04345678123456
```

It listens on TCP port `1555`. `MDComm/MDComm.cs` and `mdupdate.bat` are retained as historical generated-code artifacts; the modern emulator uses `mdemu/MDComm.fs` instead.

### Test client (`mdtest`) — Linux

For a host build, `mdtest` expects configured `libfreefare` and `libnfc` checkouts as siblings of this repository (`../libfreefare`, `../libnfc`) and links against protobuf, OpenSSL and libusb. For a reproducible build, use the Docker Booster environment in `containers/mdtest/`.

```
cd mdtest
make
./mdtest
```

The `make` step also runs `protoc` to generate `mdcomm.pb.{cpp,h}` from `../MDComm/mdcomm.proto`.

With Docker Booster already initialized as a submodule, build the Linux client without installing these tools on the host:

```
git submodule update --init --recursive
./containers/mdtest/run bash -lc 'cd mdtest && make FREEFARE_DIR=/opt/libfreefare NFC_DIR=/opt/libnfc'
./containers/mdtest/run bash -lc 'cd mdtest && ./mdtest'
```

The container Dockerfile fetches current `libnfc` and `libfreefare` sources under `/opt`, configures them, and passes those paths into the Makefile. The first run builds the Docker image; later runs reuse it unless the Dockerfile changes.

## Configuration notes

- **Emulator address is hardcoded.** The IP/port `192.168.5.107:1555` appears in `mdtest/proxydriver.cpp` and `mdtest/mdtest.cpp`; edit these to point at your running emulator.
- **Which test scenario runs is chosen at compile time.** `mdtest.cpp`'s `main()` selects one of `desfire_show_info`, `desfire_access`, `desfire_default_key` or `desfire_change_keys` with `#if (0)`/`#if (1)` blocks. Flip the blocks and rebuild to run a different scenario.
- **Cross-platform split.** The emulator targets modern .NET; the test client targets C++ on Linux and is easiest to build through Docker Booster.

## Status

This is a development/testing tool, not a complete or spec-compliant DESFire implementation. Not every command is implemented, and file encryption / 3DES coverage is partial (for example, `CMD_CHANGE_FILE_SETTINGS` is a stub).

## License

[MIT](LICENSE) © 2013-2026 Andrei Errapart
