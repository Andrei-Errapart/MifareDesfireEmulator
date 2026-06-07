# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A software emulator of a **Mifare DESFire** smartcard. There is no NFC hardware: a test client speaks the DESFire protocol over a TCP socket to an emulator process that maintains card state in memory and on disk. Used to develop and test DESFire reader logic without physical cards/readers.

## Components (three languages, three toolchains)

- **`mdemu/`** — the emulator itself. F#, .NET Framework 4.5. A TCP server (port **1555**) that decodes wrapped APDUs and behaves like a DESFire PICC. This is where ~all the real logic lives (`mdemu/mdemu.fs`, single file).
- **`MDComm/`** — the protobuf wire-protocol library shared by emulator and client. C#, .NET 3.5. `mdcomm.proto` is the source of truth; `MDComm.cs` is **generated code — do not hand-edit**.
- **`mdtest/`** — the test client. C++, Linux, plain `Makefile`. Drives the emulator using **libfreefare** as the DESFire client library, routed through a fake **libnfc** driver (`proxydriver`) that sends APDUs over TCP instead of to NFC hardware.

`mdemu.sln` builds only the .NET side (`mdemu` + `MDComm`); `mdtest` is built separately via its Makefile.

## Data flow

```
libfreefare (mdtest.cpp)          ← writes DESFire test scenarios
  → proxydriver (proxydriver.cpp) ← a fake libnfc driver; APDUs go to TCP, not hardware
  → TCP :1555, length-delimited protobuf (MessageToSlave / MessageFromSlave)
  → mdemu serve_connection (mdemu.fs)
  → MifareDesfire.Transceive       ← the command interpreter / card state machine
  → MessageFromSlave response back up the chain
```

## The core: `MifareDesfire.Transceive` (mdemu.fs)

One large `match` over command bytes (`CMD_*`) implementing the DESFire command set. Key facts to know before editing it:

- **APDU framing** (`unwrap_apdu` / `wrap_response`): request is `[0x90, CMD, 0x00, 0x00, Lc, <data...>, 0x00]`; response is `<data...> ++ [0x91, STATUS]`. Status bytes are the `STATUS_*` constants.
- **Two-mode state machine.** `Mode` is `Normal` or `Continuation`. Returning status `STATUS_ADDITIONAL_FRAME` (0xAF) puts the connection into Continuation; the next `CMD_ADDITIONAL_FRAME` (0xAF) resumes the in-progress operation via the `Continued*` fields (`ContinuedAuth`, `ContinuedReadData`, `ContinuedWriteData`, plus `VersionResponse`). Multi-frame ops (authentication handshake, GetVersion, chunked read/write) live half in the `Normal` branch and half in the `Continuation` branch — change both sides together.
- **Authentication** is the standard DESFire 3-pass mutual auth (RndA/RndB, rotate-by-one, XOR-chained). A successful handshake builds a session key and stores an `AuthResult` in `Session`; permission checks throughout the match inspect `Session.KeyId`.
- **Crypto** is 3DES in ECB with manual CBC-style chaining done in `AuthResult.BlockEncrypt/Decrypt` (the PICC always *encrypts*; decrypt differs only by when the IV XOR happens). `create_3des_encryptor_decryptor` uses **reflection to call the internal `_NewEncryptor`** specifically to bypass .NET's weak-key rejection — the DESFire default key is all-zeros and would otherwise be refused. Don't "fix" this into a normal `CreateEncryptor` call.
- **Permission model** lives on the `Application`/`Card` types: `MasterKeyConfiguration` bitmasks and per-file `AccessRights` nibbles (read/write/readwrite/change key IDs, with `KEYID_FREE_ACCESS`/`KEYID_DENY_ACCESS` sentinels).

## Persistence

Per connection, the emulator loads/saves card state as JSON at **`card-<uid>.txt`** in its working directory (`serve_connection`, via `DataContractJsonSerializer`). Missing/unreadable file → fresh default card. **Delete this file to reset a card** to factory state. The whole `Card`/`Application`/`File`/`Key` object graph is what gets serialized, so adding fields to those types changes the on-disk format.

## Build & run

**.NET side (Windows / Visual Studio 2012 / MSBuild):**
```
msbuild mdemu.sln /p:Configuration=Debug
mdemu.exe [card_uid_hex]      # 7 hex bytes, e.g. 04345678123456 (default if omitted); listens on :1555
```

**Regenerating protobuf C# (`MDComm.cs`)** — Windows only, run from `MDComm/`:
```
mdupdate.bat                  # invokes lib/protogen.exe against mdcomm.proto
```

**Test client (`mdtest`, Linux):**
```
cd mdtest && make             # also runs protoc to generate mdcomm.pb.{cpp,h} from ../MDComm/mdcomm.proto
./mdtest
```
The Makefile expects **`../libfreefare` and `../libnfc` as sibling checkouts** and links against protobuf, openssl, libusb, cppcutter. There is no automated test runner — `mdtest` is a manual program you point at a running `mdemu`.

## Gotchas

- **Hardcoded emulator address.** The IP/port `192.168.5.107:1555` is hardcoded in both `mdtest/proxydriver.cpp` and `mdtest/mdtest.cpp` (and the port `1555` in `mdemu.fs`). Edit these to match your setup.
- **Which test runs is chosen at compile time.** `mdtest.cpp` `main()` toggles scenarios (`desfire_show_info`, `desfire_access`, `desfire_default_key`, `desfire_change_keys`) with `#if (0)/#if (1)` blocks — exactly one is enabled. Flip the blocks and rebuild to run a different scenario.
- **Cross-platform split.** Emulator is .NET/Windows; client is C++/Linux. Neither builds on this macOS checkout without the respective toolchains and the libnfc/libfreefare sources.
- **Incomplete by design.** Header TODOs in `mdemu.fs` note that not every command is implemented and full file encryption/3DES coverage is partial; e.g. `CMD_CHANGE_FILE_SETTINGS` is a stub that returns a length error. Don't assume a command is fully spec-compliant — read its match arm.
