You may have seen the `SEC()` macro used around eBPF C code. This macro sends
a hint to the compiler to place a symbol (a variable or function) in a specific
section of the resulting eBPF object binary.

Typically, program binaries for Unix-like systems are divided into so-called
'sections'. All sections have names, many of which are assigned special meaning.
For example, `.text` is where [program
text](https://en.wikipedia.org/wiki/Code_segment) (executable instructions) goes
by default.

Like common application binaries, eBPF also relies heavily on section naming to
distinguish various parts of an application. As an example, the section name of
an individual eBPF program determines its program type, affecting the way the
program is verified by the kernel and defining what the program is allowed to
do.

## Executable Linkable Format (ELF)

Executable Linkable Format (ELF) is the standard application binary format for
Linux. It is also used as the output format of LLVM's BPF backend. ELF binaries
are typically [executed directly by the
kernel](https://lwn.net/Articles/631631/), but for eBPF, a different approach is
needed.

eBPF programs are not executable in the traditional sense. They depend on a user
space component that loads them, manages their resources, and can interact with
their components. This is where projects such as libbpf and {{ proj }} come
in.

For compatibility reasons, {{ proj }} follows the section naming conventions
established by libbpf, since we consider upstream decisions to be authoritative
on this subject. There's also little reason to do things differently; section
names are essentially considered an API.

??? tip "How do I explore an ELF's contents?"
    You can display an ELF's section table using `readelf -S <binary>`.

    For visualizing a program instructions or the contents of a map's data
    section, you'll need a tool from the LLVM toolchain: `llvm-objdump`. For
    example: `llvm-objdump -SD my_ebpf.o -j xdp`. This will limit output to
    the `xdp` section (see [Program Sections](#program-sections)), display
    corresponding source code lines if available using `-S`, and display
    disassembled instructions using `-D`. The same can be done for data sections
    like `.data` and `.rodata.` (see [Map Sections](#map-sections)).

    Also worth mentioning: display an eBPF object's BTF type information using
    `bpftool btf dump file my_object.o`.

## Section Prefixes

To support encoding extra information into section names, a prefix convention
using forward slashes `/` is used. For example, a Kprobe-type program meant to
be attached to the `slub_flush` kernel symbol would be put into an ELF section
called `kprobe/slub_flush`.

### Miscellaneous Sections

`license`

:   In order to use certain BPF helpers in your program, it must be licensed
    under a GPL-compatible license. BPF programs licensing follows the same
    rules as kernel module licensing. This is explained in more detail in the
    Linux kernel's [BPF licensing
    documentation](https://docs.kernel.org/bpf/bpf_licensing.html#using-bpf-programs-in-the-linux-kernel).
    See the
    [`license_is_gpl_compatible`](https://elixir.bootlin.com/linux/v6.5.4/source/include/linux/license.h)
    function in the Linux source code or the [Module Licensing
    table](https://docs.kernel.org/process/license-rules.html#id1).

    This section must only contain the license string of the programs in the
    ELF. for example: `#!c char __license[] SEC("license") = "Dual MIT/GPL";`.

`version`

:   **Deprecated.** Kernels <5.0 require this section to contain a value
    matching the kernel's `LINUX_VERSION_CODE` for Kprobe-type programs. Always
    omit this, {{ proj }} will populate this field automatically if needed.

### Map Sections

`.maps`

:   This section is dedicated to BTF-style Map definitions.

`maps`

:   **Deprecated.** This section is expected to only contain fixed-width `struct
    bpf_map_def` variables. Larger structs like iproute2's `struct bpf_elf_map`
    can also be used for backwards compatibility. Any extra bytes past the end
    of the size of a `struct bpf_map_def` are exposed by {{
    godoc('MapSpec.Extra') }} and must be drained before attempting to create
    the Map.

#### :material-head-cog: Advanced: Special Map Sections

`.data`

:   The LLVM BPF backend implements accesses to mutable global variables as
    direct Array Map accesses. Since a single BPF program can be executed
    concurrently as a result of the kernel processing packets and other events
    asynchronously, `.data` and the global variables it represents are
    considered shared memory.

    This section is exposed by {{ godoc('CollectionSpec.Maps') }} as a
    single-element BPF array and its contents are accessible through {{
    godoc('MapSpec.Contents') }}. Its layout is described by its {{
    godoc('MapSpec.Value') }}, a {{ godoc('btf/Datasec') }} containing all
    global variables in the compilation unit.

    The contents of the Map may be modified to control the default values
    used for the eBPF program's global variables.

`.rodata*`

:   Like `.data`, but for constants. This is a prefix and matches sections like
    `.rodata.foo`. Constants can be emitted to different sections using e.g.
    `#!c SEC(".rodata.foo") volatile const foobar = 123;`. This can prove useful
    for isolating certain constants to well-known sections for Go code
    generation or custom constant rewriting logic.

`.bss`

:   Section emitted by the compiler when zero-initialized globals are present in
    the ELF. Is typically zero-length. Exposed by {{
    godoc('CollectionSpec.Maps') }}, but not really useful.

`.rel*`

:   Not exposed by {{ proj }}, only used behind the scenes. Relocation sections
    contain relocation records against their non-`.rel` prefixed counterparts.
    This is mainly used for fixing up BPF instructions referring to Maps and
    global variables.

### Program Sections

Names of Program sections mainly define the program's {{ godoc('ProgramType')
}}, but also its {{ godoc('AttachType') }} and {{ godoc('AttachFlags') }} are
automatically set for convenience based on its section name.

As described previously, section prefixes containing a forward slash `/` expect
a second component to follow the slash. For example, a program in the
`kprobe/slub_flush` section will automatically have its {{
godoc('ProgramSpec.AttachTo') }} field set to `slub_flush` to facilitate
attaching the program later on.

Additionally, the program's original full section name can be found in {{
godoc('ProgramSpec.SectionName') }}.

!!! tip ""
    There's also [upstream libbpf
    documentation](https://docs.kernel.org/bpf/libbpf/program_types.html) for
    this. Not all of libbpf's program types may be supported by {{ proj }} yet.
    If a program type you require is missing, please file an issue or send a
    pull request!

| Section (Prefix)      | {{ godoc('ProgramType') }} | {{ godoc('AttachType') }}        | {{ godoc('AttachFlags') }} |
|:----------------------|:---------------------------|:---------------------------------|:---------------------------|
| socket                | SocketFilter               |                                  |                            |
| sk_reuseport/migrate  | SkReuseport                | AttachSkReuseportSelectOrMigrate |                            |
| sk_reuseport          | SkReuseport                | AttachSkReuseportSelect          |                            |
| kprobe/               | Kprobe                     |                                  |                            |
| uprobe/               | Kprobe                     |                                  |                            |
| kretprobe/            | Kprobe                     |                                  |                            |
| uretprobe/            | Kprobe                     |                                  |                            |
| tc                    | SchedCLS                   |                                  |                            |
| classifier            | SchedCLS                   |                                  |                            |
| action                | SchedACT                   |                                  |                            |
| tracepoint/           | TracePoint                 |                                  |                            |
| tp/                   | TracePoint                 |                                  |                            |
| raw_tracepoint/       | RawTracepoint              |                                  |                            |
| raw_tp/               | RawTracepoint              |                                  |                            |
| raw_tracepoint.w/     | RawTracepointWritable      |                                  |                            |
| raw_tp.w/             | RawTracepointWritable      |                                  |                            |
| tp_btf/               | Tracing                    | AttachTraceRawTp                 |                            |
| fentry/               | Tracing                    | AttachTraceFEntry                |                            |
| fmod_ret/             | Tracing                    | AttachModifyReturn               |                            |
| fexit/                | Tracing                    | AttachTraceFExit                 |                            |
| fentry.s/             | Tracing                    | AttachTraceFEntry                | BPF_F_SLEEPABLE            |
| fmod_ret.s/           | Tracing                    | AttachModifyReturn               | BPF_F_SLEEPABLE            |
| fexit.s/              | Tracing                    | AttachTraceFExit                 | BPF_F_SLEEPABLE            |
| freplace/             | Extension                  |                                  |                            |
| lsm/                  | LSM                        | AttachLSMMac                     |                            |
| lsm.s/                | LSM                        | AttachLSMMac                     | BPF_F_SLEEPABLE            |
| iter/                 | Tracing                    | AttachTraceIter                  |                            |
| iter.s/               | Tracing                    | AttachTraceIter                  | BPF_F_SLEEPABLE            |
| syscall               | Syscall                    |                                  |                            |
| xdp.frags_devmap/     | XDP                        | AttachXDPDevMap                  | BPF_F_XDP_HAS_FRAGS        |
| xdp_devmap/           | XDP                        | AttachXDPDevMap                  |                            |
| xdp.frags_cpumap/     | XDP                        | AttachXDPCPUMap                  | BPF_F_XDP_HAS_FRAGS        |
| xdp_cpumap/           | XDP                        | AttachXDPCPUMap                  |                            |
| xdp.frags             | XDP                        |                                  | BPF_F_XDP_HAS_FRAGS        |
| xdp                   | XDP                        |                                  |                            |
| perf_event            | PerfEvent                  |                                  |                            |
| lwt_in                | LWTIn                      |                                  |                            |
| lwt_out               | LWTOut                     |                                  |                            |
| lwt_xmit              | LWTXmit                    |                                  |                            |
| lwt_seg6local         | LWTSeg6Local               |                                  |                            |
| cgroup_skb/ingress    | CGroupSKB                  | AttachCGroupInetIngress          |                            |
| cgroup_skb/egress     | CGroupSKB                  | AttachCGroupInetEgress           |                            |
| cgroup/skb            | CGroupSKB                  |                                  |                            |
| cgroup/sock_create    | CGroupSock                 | AttachCGroupInetSockCreate       |                            |
| cgroup/sock_release   | CGroupSock                 | AttachCgroupInetSockRelease      |                            |
| cgroup/sock           | CGroupSock                 | AttachCGroupInetSockCreate       |                            |
| cgroup/post_bind4     | CGroupSock                 | AttachCGroupInet4PostBind        |                            |
| cgroup/post_bind6     | CGroupSock                 | AttachCGroupInet6PostBind        |                            |
| cgroup/dev            | CGroupDevice               | AttachCGroupDevice               |                            |
| sockops               | SockOps                    | AttachCGroupSockOps              |                            |
| sk_skb/stream_parser  | SkSKB                      | AttachSkSKBStreamParser          |                            |
| sk_skb/stream_verdict | SkSKB                      | AttachSkSKBStreamVerdict         |                            |
| sk_skb                | SkSKB                      |                                  |                            |
| sk_msg                | SkMsg                      | AttachSkMsgVerdict               |                            |
| lirc_mode2            | LircMode2                  | AttachLircMode2                  |                            |
| flow_dissector        | FlowDissector              | AttachFlowDissector              |                            |
| cgroup/bind4          | CGroupSockAddr             | AttachCGroupInet4Bind            |                            |
| cgroup/bind6          | CGroupSockAddr             | AttachCGroupInet6Bind            |                            |
| cgroup/connect4       | CGroupSockAddr             | AttachCGroupInet4Connect         |                            |
| cgroup/connect6       | CGroupSockAddr             | AttachCGroupInet6Connect         |                            |
| cgroup/sendmsg4       | CGroupSockAddr             | AttachCGroupUDP4Sendmsg          |                            |
| cgroup/sendmsg6       | CGroupSockAddr             | AttachCGroupUDP6Sendmsg          |                            |
| cgroup/recvmsg4       | CGroupSockAddr             | AttachCGroupUDP4Recvmsg          |                            |
| cgroup/recvmsg6       | CGroupSockAddr             | AttachCGroupUDP6Recvmsg          |                            |
| cgroup/getpeername4   | CGroupSockAddr             | AttachCgroupInet4GetPeername     |                            |
| cgroup/getpeername6   | CGroupSockAddr             | AttachCgroupInet6GetPeername     |                            |
| cgroup/getsockname4   | CGroupSockAddr             | AttachCgroupInet4GetSockname     |                            |
| cgroup/getsockname6   | CGroupSockAddr             | AttachCgroupInet6GetSockname     |                            |
| cgroup/sysctl         | CGroupSysctl               | AttachCGroupSysctl               |                            |
| cgroup/getsockopt     | CGroupSockopt              | AttachCGroupGetsockopt           |                            |
| cgroup/setsockopt     | CGroupSockopt              | AttachCGroupSetsockopt           |                            |
| struct_ops+           | StructOps                  |                                  |                            |
| sk_lookup/            | SkLookup                   | AttachSkLookup                   |                            |
| seccomp               | SocketFilter               |                                  |                            |
| kprobe.multi          | Kprobe                     | AttachTraceKprobeMulti           |                            |
| kretprobe.multi       | Kprobe                     | AttachTraceKprobeMulti           |                            |
