# Resource Limits

Creating eBPF objects (Maps, Programs, even BTF blobs) requires the kernel to
allocate memory. On kernels before 5.11, users could limit the amount of memory
available to a given process for creating eBPF objects by controlling the
process' `RLIMIT_MEMLOCK` value as displayed by the `ulimit -l` command.

!!! note
    User space itself does *not* generally allocate or `mlock(2)` any
    memory for the eBPF subsystem. `RLIMIT_MEMLOCK` was chosen early on because
    it was an existing knob related to memory management. Unfortunately, the
    approach came with major drawbacks, see the [cover
    letter](https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com) of
    the cgroup accounting introduced in 5.11.

In [version 5.11](https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com),
the Linux kernel changed from using rlimits to using memory cgroup (memcg)
accounting for tracking and enforcing memory limits on processes managing eBPF
objects in the kernel. Allocations related to eBPF objects are tracked alongside
all other regular allocations in the cgroup. Memory limits can be set using
cgroupfs, which is automatically managed by the container runtime in case of
containerized workloads.

## Purpose of package `rlimit`

On kernels supporting memcg accounting, there is no longer the need to manage
`RLIMIT_MEMLOCK` for effectively using eBPF, since allocating eBPF objects
counts towards the cgroup memory limit instead. With many pre-5.11 kernels still
shipped by various Linux distributions, it's now necessary to conditionally
manage rlimit on kernels that don't yet support memcg accounting for eBPF.

In order to support writing portable Go tools that work across a wide range of
kernel versions, the `rlimit` package was introduced. It encapsulates two main
behaviours:

1. As an **import side effect** of importing the package, it will attempt to
   lower the rlimit of the current process to induce a Map creation failure.
2. {{ godoc('rlimit/RemoveMemlock') }} will conditionally increase
   `RLIMIT_MEMLOCK` to infinity based on the result of the probe. If the kernel
   supports memcg accounting, this is a no-op.

## Usage

Simply include this somewhere in your program:

{{ go_example('DocRlimit', title="Remove RLIMIT_MEMLOCK if kernel lacks memcg accounting") }}

!!! note
    There's no harm in issuing multiple calls to `RemoveMemlock()`, for example,
    if your program has multiple entry points or CLI subcommands. The rlimit
    operation will only ever fire once.

## Caveats

### Race Conditions

The package was carefully designed with Go's runtime initialization semantics in
mind, meaning only one `init()` will execute at a time across all packages,
minimizing the risk of racing against other callers to `prlimit(2)` (which
should hopefully be rare).

The rlimit package first gets the process' current `RLIMIT_MEMLOCK` value, drops
it to 0, attempts to create a BPF map, then finally resets the rlimit to the old
value. To be clear, this happens **before invoking** `RemoveMemlock()` and has
two potential side effects:

- On kernels before 5.11, other concurrent BPF object creations may fail due to
  insufficient memory being available while the rlimit is at 0.
- Other Go packages interacting with `prlimit(2)` may interfere with this
  process, leading to a wrong `RLIMIT_MEMLOCK` value being read or restored.
  Please audit your code and dependencies for potential conflicts.

### Why does my application always create a Map on startup?

Due to the way the package is designed (creating a Map from `init()`), there is
currently no way to prevent your application from interacting with `bpf(2)` even
if `RemoveMemlock()` is never invoked or if none of your application's eBPF
features are otherwise used/enabled.

One user reported a failed security audit where the expectation was for no
`bpf(2)` interactions to take place when eBPF was disabled. The solution in this
case is to avoid using the `rlimit` package altogether and increasing the rlimit
through other means like Docker's `--ulimit memlock=-1` flag or systemd's
`LimitMEMLOCK=infinity` unit limit property.

!!! note
    The `rlimit` package is entirely optional and intended as a convenience
    feature.
