# Shipping Portable eBPF-powered Applications

!!! incomplete
    This guide builds on Getting Started.
    
    Document what the various ways are for making tools portable across kernel
    versions and what the various CO-RE techniques are.

!!! tip ""
    We recommend building eBPF C code from within a container with a stable LLVM
    toolchain, as well as checking all generated `.o` and `.go` files into
    source control. This buys you fully-reproducible builds, prevents bugs due
    to team members using different LLVM versions and makes your packages fully
    independent and `go run`nable. It also prevents PII from leaking into ELFs
    in the form of absolute paths to `.c` source files in DWARF info.

### Cross-compiling

You may have noticed bpf2go generating two sets of files:

- `*_bpfel.o` and `*_bpfel.go` for little-endian architectures like amd64,
  arm64, riscv64 and loong64
- `*_bpfeb.o` and `*_bpfeb.go` for big-endian architectures like s390(x), mips
  and sparc

Both sets of .go files contain a `//go:embed` statement that slurps the contents
of the respective .o files into a byte slice at compile time. The result is a
standalone Go application binary that can be deployed to a target machine
without any of the .o files included. To further reduce runtime dependencies,
add `CGO_ENABLED=0` to `go build` and your application won't depend on libc.
(assuming none of your other dependencies require cgo)

Moreover, because both eBPF objects and Go scaffolding are generated for both
big- and little-endian architectures, cross-compiling your Go application is as
simple as setting the right `GOARCH` value at compile time.

Pulling it all together, for building an eBPF-powered Go application for a
Raspberry Pi running a 64-bit Linux distribution:

```shell-session
CGO_ENABLED=0 GOARCH=arm64 go build
```

### Compile Once - Run Everywhere?

Since we can generate a standalone binary and deploy it to any system, does that
mean tools built using {{ proj }} will magically work anywhere? Unfortunately,
no, not really.

The kernel's internal data structures change as the kernel progresses in
development, just like any other software. Differences in compile-time
configuration affect data structures and the presence of certain kernel symbols.
This means that, even when using the exact same kernel release, no two Linux
distributions will be the same when it comes to data layout.

This is problematic for authors that want to ship a single binary to their users
and expect it to work across multiple distributions and kernel versions. In
response to this, the term *Compile Once - Run Everywhere* was coined to
describe the collection of techniques employed to achieve universal
interoperability for eBPF. This technique relies on type information encoded in
BPF Type Format (BTF) to be shipped with the kernel so memory accesses can be
adjusted right before loading the eBPF program into the kernel.

Alternatively, you may opt for shipping a full LLVM compiler toolchain along
with your application and recompiling the eBPF C against Linux kernel headers
present on the target machine. This approach is out of scope of the {{ proj }}
documentation.
