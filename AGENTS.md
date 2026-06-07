# Repository Guidelines

## Project Structure & Module Organization

This repository contains a software Mifare DESFire emulator and TCP-backed test client.

- `mdemu/`: F# .NET 8 emulator. Most card logic is in `mdemu/mdemu.fs`; it listens on TCP port `1555` and persists state as `card-<uid>.txt`.
- `MDComm/`: Protocol Buffers schema directory. `MDComm/mdcomm.proto` is the shared schema; `MDComm/MDComm.cs` is historical generated code. The modern emulator uses `mdemu/MDComm.fs`.
- `mdtest/`: Linux C++ test client and fake libnfc driver. It builds with `mdtest/Makefile` and generates `mdcomm.pb.{cpp,h}` from the shared proto.
- `mdemu.sln`: Visual Studio solution for the .NET projects.

## Build, Test, and Development Commands

- `dotnet build mdemu.sln`: builds the .NET 8 emulator.
- `dotnet run --project mdemu/mdemu.fsproj -- 04345678123456`: runs the emulator with an explicit 7-byte UID.
- `cd mdtest && make`: builds the Linux test client and runs `protoc` for C++ protobuf output.
- `cd mdtest && make clean`: removes generated objects, `mdtest`, and generated protobuf C++ files.
- `cd mdtest && ./mdtest`: runs the manual test client against a running emulator.

## Coding Style & Naming Conventions

Follow the existing style in each component. F# code uses PascalCase for types/members and command/status constants such as `CMD_*` and `STATUS_*`. C++ files use lowercase filenames and names such as `desfire_show_info`. Keep Makefile recipe indentation as tabs. Do not edit generated protobuf outputs directly; update `mdcomm.proto` and regenerate.

## Testing Guidelines

There is no standalone automated test suite. `mdtest` is the manual integration test path and depends on sibling checkouts `../libfreefare` and `../libnfc`, plus protobuf, OpenSSL, and libusb. Before running it, update the hardcoded emulator address in `mdtest/proxydriver.cpp` and `mdtest/mdtest.cpp` if needed. Test scenarios are selected in `mdtest.cpp` with `#if (0)` / `#if (1)` blocks; enable one, rebuild, then run `./mdtest`.

## Commit & Pull Request Guidelines

The current history uses short sentence-style commit messages, for example `Added some preliminary documentation.` Prefer concise past-tense summaries. Pull requests should describe the affected component (`mdemu`, `MDComm`, or `mdtest`), note protocol or persistence-format changes, list commands run, and include any manual validation scenario.

## Agent-Specific Instructions

Preserve the cross-platform split: `mdemu.sln` builds the .NET 8 emulator, while `mdtest` is built separately on Linux or through Docker Booster. When modifying DESFire command handling, review both normal and continuation paths in `mdemu/mdemu.fs`, because multi-frame operations span both states.
