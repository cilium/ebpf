# Creating an eBPF-powered Go application

!!! tip ""
    For a high-level understanding of what eBPF is and how it works, please see
    [the eBPF introduction at ebpf.io](https://ebpf.io/what-is-ebpf). This guide
    assumes familiarity with the basic concepts and terminology, as well as a
    basic understanding of the Go toolchain (`go build`). We'll also rely on `go
    generate`, see the [Go blog on Generating
    Code](https://go.dev/blog/generate) if you're not yet familiar.

    Discover [more projects using {{ proj }} here](../users.md). The main
    repository also contains an [examples
    directory](https://github.com/cilium/ebpf/tree/main/examples) with minimal
    demo applications that can be tested on any supported Linux machine.

In this guide, we'll walk you through building a new eBPF-powered Go application
from scratch. We'll introduce the toolchain, write a minimal eBPF C example and
compile it using [bpf2go](../bpf2go/index.md). Then, we'll put together a Go
application that loads the eBPF program into the kernel and periodically
displays its output.

The application attaches an eBPF program to an XDP hook that counts the number
of packets received by a physical interface. Filtering and modifying packets is
a major use case for eBPF, so you'll see a lot of its features being geared
towards it. However, eBPF's capabilities are ever-growing, and it has been
adopted for tracing, systems and application observability, security and much
more.

## eBPF C program

!!! abstract "Dependencies"
    To follow along with the example, you'll need:

    * Linux kernel version 5.7 or later, for bpf_link support
    * LLVM 7 or later
    * Go compiler version supported by {{ proj }}'s Go module
    * libbpf headers, typically in distro packages `libbpf` or `libbpf-dev`
      (Debian/Ubuntu)

Let's begin by writing our eBPF C program, as its structure will be used as the
basis for generating Go boilerplate.

Click the :material-plus-circle: annotations in the code snippet for a detailed
explanation of the individual components.

{{ c_example('getting_started_counter', title='counter.c') }}

1. When putting C files alongside Go files, they need to be excluded by a Go
   build tag, otherwise `go build` will complain with `C source files not
   allowed when not using cgo or SWIG`. The Go toolchain can safely ignore our
   eBPF C files.

1. Include headers containing the C macros used in the example. Identifiers such
   as `__u64` and `BPF_MAP_TYPE_ARRAY` are shipped by the Linux kernel, with
   `__uint`, `__type`, `SEC` and BPF helper definitions being provided by
   libbpf.

1. Declare a BPF map called `pkt_count`, an Array-type Map holding a single
   u64 value. See `man bpf` or the online [bpf man
   pages](https://man7.org/linux/man-pages/man2/bpf.2.html) for an overview of
   all available map types.<br/><br/>
   For this example, we went with an array since it's a well-known data
   structure you're likely familiar with. In BPF, arrays are preallocated and
   zeroed, making them safe and ready to use without any initialization.

1. The Map definition is placed in the `.maps` ELF section, which is where {{
   proj }} expects to find it.

1. In BPF, not all programs are equal. Some act on raw packets, some execute
   within the context of kernel or user space functions, while others expect to
   be run against an `__sk_buff`. These differences are encoded in the Program
   Type. libbpf introduced a set of conventions around which ELF sections
   correspond to which type. In this example, we've chosen `xdp` since we'll
   attach this program to the XDP hook later.

1. There's only one possible element in `pkt_count` since we've specified a
   `max_entries` value of 1. We'll always access the 0th element of the array.

1. Here, we're asking the BPF runtime for a pointer to the 0th element of the
   `pkt_count` Map. <br/><br/>
   `bpf_map_lookup_elem` is a BPF helper declared in `docs.h`. Helpers are small
   pieces of logic provided by the kernel that enable a BPF program to interact
   with its context or other parts of the kernel. Discover all BPF helpers
    supported by your kernel using `man bpf-helpers` or the online [bpf-helpers
    man pages](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).

1. All Map lookups can fail. If there's no element for the requested `key` in
   the Map, `count` will hold a null pointer. The BPF verifier is very strict
   about checking access to potential null pointers, so any further access
   to `count` needs to be gated by a null check.

1. Atomically increase the value pointed to by `count` by 1. It's important to
   note that on systems with SMP enabled (most systems nowadays), the same BPF
   program can be executed concurrently.<br/><br/>
   Even though we're loading only one 'copy' of our Program, accompanied by a
   single `pkt_count` Map, the kernel may need to process incoming packets on
   multiple receive queues in parallel, leading to multiple instances of the
   program being executed, and `pkt_count` effectively becoming a piece of
   shared memory. Use atomics to avoid dirty reads/writes.

1. XDP allows for dropping packets early, way before it's passed to the kernel's
   networking stack where routing, firewalling (ip/nftables) and things like TCP
   and sockets are implemented. We issue the `XDP_PASS` verdict to avoid ever
   interfering with the kernel's network stack.

1. Since some BPF helpers allow calling kernel code licensed under GPLv2, BPF
   programs using specific helpers need to declare they're (at least partially)
   licensed under GPL. Dual-licensing is possible, which we've opted for here
   with `Dual MIT/GPL`, since {{ proj }} is MIT-licensed.

Create an empty directory and save this file as `counter.c`. In the next step,
we'll set up the necessary bits to compile our eBPF C program using `bpf2go`.

## Compile eBPF C and generate scaffolding using bpf2go

With the `counter.c` source file in place, create another file called `gen.go`
containing a `//go:generate` statement. This invokes `bpf2go` when running `go
generate` in the project directory.

{{ go_example('getting_started_gen', title='gen.go') }}

!!! tip ""
    Using a dedicated file for your package's `//go:generate` statement(s) is
    neat for keeping them separated from application logic. At this point in the
    guide, we don't have a `main.go` file yet. Feel free to include it in
    existing Go source files if you prefer.

Before using the Go toolchain, Go wants us to declare a Go module. This command
should take care of that:

```shell-session
% go mod init ebpf-test
go: creating new go.mod: module ebpf-test
go: to add module requirements and sums:
    go mod tidy
% go mod tidy
```

We also need to manually add a dependency on `bpf2go` since it's not explicitly
imported by a `.go` source file:

```shell-session
% go get github.com/cilium/ebpf/cmd/bpf2go
go: added github.com/cilium/ebpf v0.11.0
go: added golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2
go: added golang.org/x/sys v0.6.0
```

Now we're ready to run `go generate`: 

```shell-session
% go generate
Compiled /home/timo/getting_started/counter_bpfel.o
Stripped /home/timo/getting_started/counter_bpfel.o
Wrote /home/timo/getting_started/counter_bpfel.go
Compiled /home/timo/getting_started/counter_bpfeb.o
Stripped /home/timo/getting_started/counter_bpfeb.o
Wrote /home/timo/getting_started/counter_bpfeb.go
```

`bpf2go` built `counter.c` into `counter_bpf*.o` behind the scenes using
`clang`. It generated two object files and two corresponding Go source files
based on the contents of the object files. Do not remove any of these, we'll
need them later.

Let's inspect one of the generated .go files:

{{ go_example('counterPrograms', title='counter_bpfel.go', signature=True) }}

Neat! Looks like bpf2go automatically generated a scaffolding for interacting
with our `count_packets` Program from Go. In the next step, we'll explore how to
load our program into the kernel and put it to work by attaching it to an XDP
hook!

## The Go application

Finally, with our eBPF C code compiled and Go scaffolding generated, all that's
left is writing the Go code responsible for loading and attaching the program to
a hook in the Linux kernel.

Click the :material-plus-circle: annotations in the code snippet for some of the
more intricate details. Note that we won't cover anything related to the Go
standard library here.

{{ go_example('getting_started_main', title='main.go') }}

1. Linux kernels before 5.11 use RLIMIT_MEMLOCK to control the maximum amount of
   memory allocated for a process' eBPF resources. By default, it's set to a
   relatively low value. See [Resource Limits](rlimit.md) for a deep dive.

1. `counterObjects` is a struct containing nil pointers to Map and Program
   objects. A subsequent call to `loadCounterObjects` populates these fields
   based on the struct tags declared on them. This mechanism saves a lot of
   repetition that would occur by checking a Collection for Map and Program
   objects by string.<br/><br/>
   As an added bonus, `counterObjects` adds type safety by turning these into
   compile-time lookups. If a Map or Program doesn't appear in the ELF, it won't
   appear as a struct field and your Go application won't compile, eliminating
   a whole class of runtime errors.

1. Close all file descriptors held by `objs` right before the Go application
   terminates. See [Object Lifecycle](../loading/object-lifecycle.md) for a
   deep dive.

1. Associate the `count_packets` (stylized in the Go scaffolding as
   `CountPackets`) eBPF program with `eth0`. This returns a {{
   godoc('link/Link') }} abstraction. See [Attaching](../programs/attaching.md)
   for a deep dive.

1. Close the file descriptor of the Program-to-interface association. Note that
   this will stop the Program from executing on incoming packets if the Link was
   not {{ godoc('link/Link.Pin') }}ed to the bpf file system.

1. Load a uint64 stored at index 0 from the `pkt_count` Map (stylized in the Go
   scaffolding as `PktCount`). This corresponds to the logic in `counter.c`.

Save this file as `main.go` in the same directory alongside `counter.c` and
`gen.go`.

## Building and running the Go application

Now `main.go` is in place, we can finally compile and run our Go application!

```shell-session
% go build -o getting_started && sudo ./getting_started
2023/09/20 17:18:43 Counting incoming packets on eth0..
2023/09/20 17:18:47 Received 0 packets
2023/09/20 17:18:48 Received 4 packets
2023/09/20 17:18:49 Received 11 packets
2023/09/20 17:18:50 Received 15 packets
```

Generate some traffic on eth0 and you should see the counter increase.

### Iteration Workflow

When iterating on the C and Go code simultaneously, make sure to keep generated
files up-to-date. Without re-running bpf2go, the eBPF C won't be recompiled, and
any changes made to the C program structure won't be reflected in the Go
scaffolding.

```shell-session
% go generate && go build -o getting_started && sudo ./getting_started
```

!!! tip ""
    We recommend building eBPF C code from within a container with a stable LLVM
    toolchain, as well as checking all generated `.o` and `.go` files into
    source control. This buys you fully-reproducible builds, prevents bugs due
    to team members using different LLVM versions and makes your packages fully
    independent and `go run`nable. It also prevents PII from leaking into ELFs
    in the form of absolute paths to `.c` source files in DWARF info.

## Notes on Portability

### Cross-compiling

You may have noticed bpf2go generating two sets of files:

- `*_bpfel.o` and `*_bpfel.go` for little-endian architectures like amd64,
  arm64, riscv64 and loong64
- `*_bpfel.o` and `*_bpfel.go` for big-endian architectures like s390(x), mips
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

!!! tip ""
    There's a dedicated section on [CO-RE](../loading/core.md) that explores this
    topic in detail.

Alternatively, you may opt for shipping a full LLVM compiler toolchain along
with your application and recompiling the eBPF C against Linux kernel headers
present on the target machine. This approach is out of scope of the {{ proj }}
documentation.
