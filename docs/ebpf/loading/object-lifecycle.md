!!! info ""
    This is an advanced topic and does not need to be fully understood in order
    to get started writing useful tools.

    If you find yourself debugging unexpectedly-detached programs, resource
    leaks, or you want to gain a deeper understanding of how eBPF objects are
    managed by {{ proj }}, this document should provide some insights.

## File Descriptors and Go

Interacting with eBPF objects from user space is done using file descriptors.
Counter-intuitively, 'file' descriptors are used as references to many types of
kernel resources in modern Linux, not just files.

In {{ proj }}, file descriptors are modeled using the internal abstraction {{
godoc('internal/sys/FD') }}. FD is embedded in all Go objects that represent
live eBPF resources in the kernel, and allows managing the lifecycle of the
underlying file descriptor along with the lifecycle of a Go type that embeds it
(e.g. a Map).

!!! internal inline end "FD's Runtime Finalizer"
    An `FD` is configured with a runtime finalizer calling `FD.Close()` when it
    is garbage collected.

Go, being a garbage-collected language, automatically manages the lifecycle of
Go objects. Keeping in line with the standard library's `os.File` and friends,
`FD` was designed in a way so its underlying file descriptor is closed when an
`FD` is garbage collected. This generally prevents runaway resource leaks, but
is not without its drawbacks.

The finalizer has subtle but important repercussions for BPF, since this means
the Go runtime can call `Close()` on a Map's `FD` if the Map is no longer
reachable by the garbage collector, e.g. if it was created by a function, but
not returned by it. One type of map, {{ godoc('ProgramArray') }}, is
particularly sensitive to this; more about that in a dedicated section below.

## Reference Counting

Within the **kernel**, lifetimes of eBPF objects are managed using [Reference
Counting](https://en.wikipedia.org/wiki/Reference_counting). When an object's
reference count reaches 0, it is destroyed and no longer usable.

An object's refcount is set to 1 when it is first created and a file descriptor
is issued to the calling user space application.

To increase an object's refcount:

- [Attach/link it to a hook](../programs/attaching.md)
- [Pin it to bpffs](#pinning-bpffs)
- Duplicate one of its file descriptors

To decrease an object's refcount

- Detach/unlink it from a hook
- Unpin it from bpffs
- Close a file descriptor

If an object has no open file descriptors (all closed, or its creating user
space application terminated), no existing bpffs pins, and no links/attachments
to any kernel hooks, the object's refcount will drop to 0. Its destructor will
be run and any associated memory will be freed.

## Pinning (bpffs)

One method of bumping an eBPF object's refcount is called 'pinning'. This is
done through the BPF File System (or bpffs for short), a virtual file system
provided by the kernel. It allows a user space process to associate an eBPF
object with a file, similar to organizing files and directories in an ordinary
file system. This way, when the user space process exits, the bpffs pin will
maintain the object's refcount, preventing it from being automatically
destroyed.

Another common use case for pinning is sharing eBPF objects between processes.
For example, one could create a Map using {{ proj }}, pin it, and inspect it
using `bpftool map dump pinned /sys/fs/bpf/my_map`.

Objects that benefit most from pinning are Maps ({{ godoc('Map.Pin') }}) and
Links ({{ godoc('link/Link.Pin') }}, more on that in the
[Attaching](../programs/attaching.md) section).

To unpin an object, call e.g. {{ godoc('Map.Unpin') }} or simply remove the file
from bpffs if there are no open Go objects.

## :warning: Program Arrays

A {{ godoc('ProgramArray') }} is a Map type that holds references to other
Programs. Before bpf2bpf calls became possible, it was the only way of splitting
up an eBPF program into separate parts/functions.

They have a special property: they allow cyclic dependencies to be created
between the Program Array and a Program (e.g. allowing Programs to call into
themselves).

To simplify the Map's refcounting implementation in the kernel, and to avoid
ending up with a set of Programs that cannot be freed, two rules were added:

- **Program Arrays require at least one open file descriptor or bpffs pin**.
- If no user space or bpffs references exist, **all the Map's entries are
  removed**.

!!! warning
    If all user space/bpffs references are gone, a Program may still retain a
    reference to a Program Array, but any tail calls into the array with fail.
    This property, combined with {{ proj }}'s interactions with the garbage
    collector described in [File Descriptors and Go](#file-descriptors-and-go),
    has led to a few surprises over the years.

A few tips to handle this problem correctly:

- Use {{ godoc('CollectionSpec.LoadAndAssign') }}. It will refuse to load the
  CollectionSpec if doing so would result in a Program Array without a userspace
  reference.
- Always pin Program Arrays if execution of your eBPF code needs to continue
  if/when the user space application exits, e.g. for upgrades or because you're
  building a short-lived tool.
- Make sure to retain references to the Map at all times in long-running
  applications. Note that `defer m.Close()` also acts as an implicit reference,
  at least until the enclosing function returns.
