# Repository Guidelines

## Project Structure & Module Organization

This repository contains a software Mifare DESFire emulator and TCP-backed test client.

- `mdemu/`: F# .NET Framework 4.5 emulator. Most card logic is in `mdemu/mdemu.fs`; it listens on TCP port `1555` and persists state as `card-<uid>.txt`.
- `MDComm/`: C# .NET 3.5 protobuf protocol library. `MDComm/mdcomm.proto` is the source; `MDComm/MDComm.cs` is generated and should not be hand-edited.
- `mdtest/`: Linux C++ test client and fake libnfc driver. It builds with `mdtest/Makefile` and generates `mdcomm.pb.{cpp,h}` from the shared proto.
- `mdemu.sln`: Visual Studio solution for the .NET projects.

## Build, Test, and Development Commands

- `msbuild mdemu.sln /p:Configuration=Debug`: builds `mdemu` and `MDComm` on Windows with Visual Studio/MSBuild tooling.
- `mdemu.exe 04345678123456`: runs the emulator with an explicit 7-byte UID; omit the argument to use the default.
- `cd MDComm && mdupdate.bat`: regenerates `MDComm.cs` after changing `mdcomm.proto`.
- `cd mdtest && make`: builds the Linux test client and runs `protoc` for C++ protobuf output.
- `cd mdtest && make clean`: removes generated objects, `mdtest`, and generated protobuf C++ files.
- `cd mdtest && ./mdtest`: runs the manual test client against a running emulator.

## Coding Style & Naming Conventions

Follow the existing style in each component. F# code uses PascalCase for types/members and command/status constants such as `CMD_*` and `STATUS_*`. C++ files use lowercase filenames and names such as `desfire_show_info`. Keep Makefile recipe indentation as tabs. Do not edit generated protobuf outputs directly; update `mdcomm.proto` and regenerate.

## Testing Guidelines

There is no standalone automated test suite. `mdtest` is the manual integration test path and depends on sibling checkouts `../libfreefare` and `../libnfc`, plus protobuf, OpenSSL, libusb, and cppcutter. Before running it, update the hardcoded emulator address in `mdtest/proxydriver.cpp` and `mdtest/mdtest.cpp` if needed. Test scenarios are selected in `mdtest.cpp` with `#if (0)` / `#if (1)` blocks; enable one, rebuild, then run `./mdtest`.

## Commit & Pull Request Guidelines

The current history uses short sentence-style commit messages, for example `Added some preliminary documentation.` Prefer concise past-tense summaries. Pull requests should describe the affected component (`mdemu`, `MDComm`, or `mdtest`), note protocol or persistence-format changes, list commands run, and include any manual validation scenario.

## Agent-Specific Instructions

Preserve the cross-platform split: `mdemu.sln` is for the .NET side, while `mdtest` is built separately on Linux. When modifying DESFire command handling, review both normal and continuation paths in `mdemu/mdemu.fs`, because multi-frame operations span both states.
