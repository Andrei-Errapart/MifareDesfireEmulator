# Mifare DESFire Emulator

A software emulator of a [Mifare DESFire](https://en.wikipedia.org/wiki/MIFARE#MIFARE_DESFire) smartcard. There is **no NFC hardware involved** — a test client speaks the DESFire protocol over a TCP socket to an emulator process that maintains card state in memory and on disk. This lets you develop and test DESFire reader logic without physical cards or readers.

## Components

| Directory  | Language / toolchain     | Role                                                                                  |
|------------|--------------------------|---------------------------------------------------------------------------------------|
| `mdemu/`   | F#, .NET Framework 4.5   | The emulator. A TCP server (port `1555`) that behaves like a DESFire card (PICC). All the card logic lives in `mdemu.fs`. |
| `MDComm/`  | C#, .NET 3.5             | The protobuf wire-protocol library shared by emulator and client. `mdcomm.proto` is the source; `MDComm.cs` is generated. |
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

### Emulator (`mdemu` + `MDComm`) — Windows / .NET

Open `mdemu.sln` in Visual Studio 2012 (or newer), or build from the command line:

```
msbuild mdemu.sln /p:Configuration=Debug
```

Run the emulator, optionally passing a 7-byte card UID as hex (defaults to `04345678123456`):

```
mdemu.exe 04345678123456
```

It listens on TCP port `1555`.

To regenerate `MDComm.cs` from `mdcomm.proto` after editing the protocol (Windows, run from `MDComm/`):

```
mdupdate.bat
```

### Test client (`mdtest`) — Linux

`mdtest` expects `libfreefare` and `libnfc` checked out as siblings of this repository (`../libfreefare`, `../libnfc`) and links against protobuf, OpenSSL, libusb and cppcutter.

```
cd mdtest
make
./mdtest
```

The `make` step also runs `protoc` to generate `mdcomm.pb.{cpp,h}` from `../MDComm/mdcomm.proto`.

## Configuration notes

- **Emulator address is hardcoded.** The IP/port `192.168.5.107:1555` appears in `mdtest/proxydriver.cpp` and `mdtest/mdtest.cpp`; edit these to point at your running emulator.
- **Which test scenario runs is chosen at compile time.** `mdtest.cpp`'s `main()` selects one of `desfire_show_info`, `desfire_access`, `desfire_default_key` or `desfire_change_keys` with `#if (0)`/`#if (1)` blocks. Flip the blocks and rebuild to run a different scenario.
- **Cross-platform split.** The emulator targets .NET on Windows; the test client targets C++ on Linux.

## Status

This is a development/testing tool, not a complete or spec-compliant DESFire implementation. Not every command is implemented, and file encryption / 3DES coverage is partial (for example, `CMD_CHANGE_FILE_SETTINGS` is a stub).

## License

[MIT](LICENSE) © 2013-2026 Andrei Errapart
