# Resource Limits

Creating eBPF objects (Maps, Programs, even BTF blobs) requires kernel memory
allocation. Before kernel version 5.11, you could control the memory available
to a process for creating eBPF objects by adjusting the process'
`RLIMIT_MEMLOCK` rlimit value, visible through the `ulimit -l` command.

!!! note ""
    User space typically does *not* allocate or `mlock(2)` memory for the
    eBPF subsystem. The choice of `RLIMIT_MEMLOCK` was made early on due to its
    connection to memory management. Unfortunately, this approach had
    significant drawbacks, as explained in the [cover
    letter](https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com) of
    the cgroup accounting introduced in 5.11.

Starting with [version
5.11](https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com), the
Linux kernel switched from rlimits to memory cgroup (memcg) accounting for
managing memory limits on processes handling eBPF objects in the kernel. eBPF
object allocations are tracked alongside regular allocations within the cgroup.
Memory consumption and limits can be queried and set through cgroupfs, the same
mechanism used for setting memory limits on containers.

## Purpose of package `rlimit`

On kernels supporting memcg accounting, there's no need to manage
`RLIMIT_MEMLOCK` for effectively using eBPF, as eBPF object allocations now
count towards the cgroup memory limit instead. However, since many Linux
distributions still ship pre-5.11 kernels, it's necessary to conditionally
manage rlimit for kernels lacking memcg accounting for eBPF.

To support writing portable Go tools that work across various kernel versions,
the `rlimit` package was introduced. It encapsulates two behaviours:

1. As an **import side effect** of importing the package, it lowers the rlimit
   of the current process to induce a Map creation failure, then restores the
   original rlimit.
2. {{ godoc('rlimit/RemoveMemlock') }} conditionally increases `RLIMIT_MEMLOCK`
   to infinity based on the probe's result. If the kernel supports memcg
   accounting, this is a no-op.

## Usage

Include this in your application:

{{ go_example('DocRlimit', title="Remove RLIMIT_MEMLOCK if kernel lacks memcg accounting") }}

!!! note ""
    You can call `RemoveMemlock()` multiple times it your program has
    multiple entry points or CLI subcommands. The rlimit operation will only
    execute once.

## Caveats

### Race Conditions

The package was carefully designed with Go's runtime initialization semantics in
mind, meaning only one `init()` will execute at a time across all packages,
minimizing the risk of racing against other callers to `prlimit(2)` (which
should hopefully be rare).

The rlimit package first gets the process' current `RLIMIT_MEMLOCK` value, drops
it to 0, attempts to create a BPF map, then finally resets the rlimit to the old
value. It's important to note that this happens **before invoking**
`RemoveMemlock()` and has two potential side effects:

- On kernels before 5.11, other concurrent BPF object creations may fail due to
  insufficient memory being available while the rlimit is at 0.
- Other Go packages interacting with `prlimit(2)` may interfere with this
  process, leading to a wrong `RLIMIT_MEMLOCK` value being read or restored.
  Please audit your code and dependencies for potential conflicts.

### Why does my application always create a Map on startup?

Due to the package's design (creating a Map from `init()`), there is currently
no way to prevent your application from interacting with `bpf(2)`, even if
`RemoveMemlock()` is never invoked or if none of your application's eBPF
features remain disabled.

One user reported a failed security audit that expected no `bpf(2)` interactions
to take place when eBPF features were disabled. In such cases, you can avoid
using package `rlimit` altogether and increase the rlimit through other means
like Docker's `--ulimit memlock=-1` flag or systemd's `LimitMEMLOCK=infinity`
unit limit property.

!!! note ""
    The `rlimit` package is entirely optional and serves as a convenience
    feature.
