# How to work on the Windows port

The library has basic support for interacting with eBPF for Windows (efW).
Things are subject to change because eBPF for Windows has not had a stable (signed) release yet.

## Differences between Linux and eBPF for Windows

* eBPF for Windows has three distinct modes of operation: an interpreter, a JIT
  and a way to compile eBPF to a native Windows driver. The native driver can
  be signed using the usual mechanisms. It is likely that a stable release of
  eBPF for Windows will only support native drivers. For that reason the library
  only supports loading programs from signed drivers. `NewProgram` and related
  API are not supported.
* eBPF for Windows has a large user-space component which ebpf-go calls into
  via dynamic runtime linking. This uses the same infrastructure as CGo but
  does not require a C toolchain and is therefore trivial to distribute.
  It is harder to debug and has higher overheads however.

## Exported API

The library only supports a subset of the full API on Windows, because the eBPF for
Windows runtime doesn't yet or never will support certain features.

* Package `ebpf`, `asm` and `btf` export the same API, but many functions
  will return a new sentinel error `ErrNotSupportedOnOS`. The idea is that
  `Map` and `Program` will eventually converge between the two platforms.
  Exposing the same API across OS minimises the amount of changes we need to
  make to these foundational packages and their dependents.
* Package `rlimit` exposes the same API but becomes a no-op.
* Package `link` retains the same `Link` abstraction but only exposes link types supported by Windows.
* Other packages are not available on Windows.

## Development setup

The port is developed using a Windows VM running on a Linux host.
There is a [script](../../../scripts/windows/) which automates the Windows
installation. After the installation finishes you should be able to SSH to
the VM and [follow the instructions to clone and build eBPF for Windows][efw-clone].
__Execute `Import-VsEnv` (installed by the setup script) to add `msbuild` to PATH.__

```
PS C:\Users\lmbauer> Import-VsEnv
**********************************************************************
** Visual Studio 2022 Developer PowerShell v17.10.4
** Copyright (c) 2022 Microsoft Corporation
**********************************************************************
PS C:\Users\lmbauer> msbuild
MSBuild version 17.10.4+10fbfbf2e for .NET Framework
MSBUILD : error MSB1003: Specify a project or solution file. The current working directory does not contain a project or solution file.
```

After compilation finishes you can install the runtime:

```
.\x64\Debug\setup-ebpf.ps1
```

_(You can pass `-Uninstall` to the script to remove a previous installation. This currently runs into an [annoying bug], however.)_

You can now run the Go unit tests of the library:

```
go test ./internal/sys
```

## Debugging

Debugging on Windows is a bit painful, since we call from Go into `ebpfapi.dll`
which is implemented in C++. There is currently no debugger which understands
both C++ and Go.

The most fruitful approach is to use [CDB] which is a bit like the Windows equivalent of `gdb`.
It will catch exceptions in C++ code and give useful backtraces. In theory it is
possible to use this via the command line:

```
cd internal/sys
go test -c .
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" -o .\sys.test.exe
```

__However debugging with CDB via ssh doesn't seem to work__. Instead you need to run
the [WinDbg] GUI as an administrator and then open the executable via `Ctrl-E`.

At the CDB / WinDbg prompt you can set a breakpoint on `bpf()`:

```
bu ebpfapi!bpf
g
```

This will halt execution once the library calls into `bpf()` inside `ebpfapi.dll`.
Use the [`CDB` commands][cdb-commands] or the GUI to navigate.

### Windows trace log

The `testmain` package has a small bit of instrumentation which enables tracing
of the efW subsystem before executing tests. An abbreviated version of the log
is emitted to stderr in case any tests fail.

Enabling the instrumentation can fail if the tests crashed too often. In that
case you can manually stop and remove the tracing entries via the GUI:
`compmgmt.msc` -> "Performance" -> "Data Collector Sets" -> "Event Trace Sessions".
Look for sessions containing "ebpf-go".
Rebooting might also help.

### Interpreting error codes

efW uses several layers of error codes.

* Windows [system error codes] and [RPC errors] are sometimes exposed by
  exceptions, which appear in the trace log.
* [`ebpf_result_t`][ebpf_result_t]: wraps Windows errors and
  is returned from "native" efW API.
* Unix-style errno, as defined by Windows' [`errno.h`][errno.h]:
  wraps `ebpf_result_t` and is returned from libbpf and `bpf()` API.
  Unfortunately not all [errno values] line up with Linux.
  This usually manifests in cryptic `Errno(119)` errors.

[efw-clone]: https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#how-to-clone-and-build-the-project-using-visual-studio
[annoying bug]: https://github.com/microsoft/ebpf-for-windows/issues/3760
[CDB]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-cdb-and-ntsd
[cdb-commands]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/commands
[WinDbg]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
[ebpf_result_t]: https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_result.h
[system error codes]: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
[RPC errors]: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-
[errno.h]: https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-constants?view=msvc-170
[errno values]: https://github.com/microsoft/ebpf-for-windows/issues/3729#issuecomment-2289025455
