# Working on the Windows port

The library has basic support for interacting with eBPF for Windows (efW).
Things are subject to change because eBPF for Windows has not had a stable (signed) release yet.

## Differences between Linux and eBPF for Windows

* eBPF for Windows has three distinct modes of operation: an interpreter, a JIT
  and a way to compile eBPF to a native Windows driver. The native driver can
  be signed using the usual mechanisms. It is likely that a stable release of
  eBPF for Windows will only support native drivers.
  The library supports both mechanisms, and relies on the JIT for its testsuite.
  This is because the native Windows driver mechanism still comes with significant
  downsides.
* eBPF for Windows has a large user-space component which ebpf-go calls into
  via dynamic runtime linking. This uses the same infrastructure as CGo but
  does not require a C toolchain and is therefore trivial to distribute.

## Exported API

The library only supports a subset of the full API on Windows, because the eBPF for
Windows runtime doesn't yet or never will support certain features. API which
are not supported will return `ErrNotSupported`. Some interfaces such as Linux-specific
link types are removed outright, but this is kept to a minimum since it is very
cumbersome for users to deal with API that change based on platform.

## Development setup

The port is developed using a Windows VM running on a Linux host.
There is a [script](https://github.com/cilium/ebpf/tree/main/scripts/windows)
which automates the Windows installation.
After the installation finishes you should be able to SSH to
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

!!! note "Pre-built eBPF for Windows binaries"
    You may be able to download precompiled binaries from the [efW CI/CD] pipeline.
    Look for an artifact called "Build-x64-Debug", which should contain
    `setup-ebpf.ps1` mentioned below.

After compilation finishes you can install the runtime:

```
.\x64\Debug\setup-ebpf.ps1
```

_(You can pass `-Uninstall` to the script to remove a previous installation.)_

You can now run the Go unit tests of the library:

```
go test ./internal/sys
```

!!! note "Tests fail with `load ebpfapi.dll: not found`"
    This usually means that either the Windows runtime is not installed or that
    the efW installation folder is not on the PATH yet. The latter tends to
    happen when executing tests via ssh, since sshd doesn't pick up
    changes in the environment without restarting.
    Restart the service by issuing `Restart-Service sshd` from a powershell
    prompt and then re-establish the ssh session.

### efW extensions

efW separates the runtime from the implementation of the various hooks / program
types. The hooks are shipped as extensions in a separate Windows kernel service.
Installing an extension involves two steps:

1. Installing the extension as a Windows kernel service.
2. Registering the program type(s) in the "eBPF Store".

For [ntosebpfext] the setup process looks as follows, assuming the extension has
already been built:

```
PS C:\Users\lorenz\ntosebpfext> .\tests\process_monitor.Tests\Setup-ProcessMonitorTests.ps1 -ArtifactsRoot .\x64\Debug\
Creating and starting the ntosebpfext service from C:\Users\lorenz\ntosebpfext\x64\Debug\\ntosebpfext.sys.
PS C:\Users\lorenz\ntosebpfext> .\x64\Debug\ntos_ebpf_ext_export_program_info.exe
Exporting program information.
Exporting section information.
```

## Debugging

Debugging on Windows is a bit painful, since we call from Go into `ebpfapi.dll`
which is implemented in C++. There is currently no debugger which understands
both C++ and Go.

The most fruitful approach is to use [WinDbg].
It will catch exceptions in C++ code, give useful backtraces and allows stepping
through source code.

Run the WinDbg GUI as an administrator and then open the executable via `Ctrl-E`.
At the prompt you can set a breakpoint on `bpf()`:

```
bu ebpfapi!bpf
g
```

This will halt execution once the library calls into `bpf()` inside `ebpfapi.dll`.
Use the [`CDB` commands][cdb-commands] or the GUI to navigate.

It may be possible to use [CDB] to debug via the command line, but this doesn't
seem to work via ssh.

### Windows trace log

The `testmain` package has a small bit of instrumentation which enables tracing
of the efW subsystem on demand. Simply pass the `-trace-log` flag when running
tests:

```
PS C:\Users\lorenz\ebpf> go test -run '^TestMap$' -v -trace-log
=== RUN   TestMap
    map_test.go:54: WindowsArray#3
--- PASS: TestMap (0.02s)
PASS
100%  [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
  base       ebpf_api_initiate returned success
  entry-exit ebpf_map_create
  entry-exit _create_map
  entry-exit _ebpf_core_protocol_create_map
  entry-exit ebpf_core_create_map
  entry-exit ebpf_map_create
  base       eBPF object initialized                                 object=0xFFFF8982A875BF30 object_type=       1
  base       ebpf_map_create returned success
  entry-exit ebpf_handle_create
  core       ebpf_handle_create: returning handle                    value=376
  base       ebpf_handle_create returned success
  base       ebpf_core_create_map returned success
...
```

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
[CDB]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-cdb-and-ntsd
[cdb-commands]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/commands
[WinDbg]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
[ebpf_result_t]: https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_result.h
[system error codes]: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
[RPC errors]: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-
[errno.h]: https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-constants?view=msvc-170
[errno values]: https://github.com/microsoft/ebpf-for-windows/issues/3729#issuecomment-2289025455
[ntosebpfext]: https://github.com/microsoft/ntosebpfext
[access the debug version of the msvc runtime]: https://github.com/microsoft/ebpf-for-windows/issues/3872
[msvc debug DLLs]: https://github.com/microsoft/ebpf-for-windows/blob/7005b7ff47e7281843d6b414cd69fc5a979507c8/scripts/setup-ebpf.ps1#L17-L27
[efW CI/CD]: https://github.com/microsoft/ebpf-for-windows/actions/workflows/cicd.yml?query=branch%3Amain+is%3Acompleted
