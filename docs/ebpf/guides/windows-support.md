# Windows support

The library has preliminary support for the [eBPF for Windows] runtime, allowing
you to build Go applications for Windows using the same APIs as on Linux.

!!! warning "Feature parity"
    efW doesn't have feature parity with Linux. Many APIs in
    the library will return `ErrNotSupported` in this case.

!!! warning "Binary compatibility"
    efW is not binary compatible with Linux. It is not possible
    to compile an eBPF program for Linux and use it on Windows.

## Platform specific constants

efW only provides [source compatibility] with Linux.
While certain Linux map or program types have an equivalent on Windows, they
don't always behave the same.

For this reason, the various type enumerations have completely distinct values
on Windows, for example `WindowsHashMap` is the equivalent of `HashMap`.
Attempting to create a `HashMap` on Windows will return an error, and vice versa.

## Platform specific ELFs

!!! note ""
    Loading Windows ELFs is not supported yet.

ELFs compiled against Linux and Windows headers are not binary compatible.
Add the following to ELFs targeting Windows until there is an
[official way to declare the platform](https://github.com/microsoft/ebpf-for-windows/issues/3956):

```C
const bool __ebpf_for_windows_tag __attribute__((section(".ebpf_for_windows"))) = true;
```

## Working with signed programs

The runtime will most likely require all eBPF programs to be signed by
Microsoft. Signing programs relies on packaging eBPF `.c` files as drivers using
the [native code pipeline], converting bytecode into a `.sys` file.

The interface to load such drivers does not allow modifying the bytecode or map
definitions, therefore you can't interact with them via `CollectionSpec`, etc.
Instead you must load them via `LoadCollection`:

```go
coll, err := LoadCollection("path\\to\\driver.sys")
```

The returned Collection contains Maps and Programs which you can interact with
as usual.

[eBPF for Windows]: https://github.com/microsoft/ebpf-for-windows
[source compatibility]: https://github.com/microsoft/ebpf-for-windows?tab=readme-ov-file#2-does-this-provide-app-compatibility-with-ebpf-programs-written-for-linux
[native code pipeline]: https://github.com/microsoft/ebpf-for-windows/blob/main/docs/NativeCodeGeneration.md
[LoadCollection]: https://pkg.go.dev/github.com/cilium/ebpf#LoadCollection
