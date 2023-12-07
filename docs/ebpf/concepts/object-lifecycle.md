!!! info ""
    This is an advanced topic and does not need to be fully understood in order
    to get started writing useful tools.

    If you find yourself debugging unexpectedly-detached programs, resource
    leaks, or you want to gain a deeper understanding of how eBPF objects are
    managed by {{ proj }}, this page should prove helpful.

## File Descriptors and Go

Interacting with eBPF objects from user space is done using file descriptors.
Counter-intuitively, 'file' descriptors are used as references to many types of
kernel resources in modern Linux, not just files. In {{ proj }}, {{ godoc('Map')
}}, {{ godoc('Program') }} and {{ godoc('link/Link') }} are all modeled around
these underlying file descriptors.

Go, being a garbage-collected language, automatically manages the lifecycle of
Go objects. Keeping in line with the standard library's `os.File` and friends,
eBPF resources in {{ proj }} were designed in a way so their underlying file
descriptors are closed when their Go objects are garbage collected. This
generally prevents runaway resource leaks, but is not without its drawbacks.

This has subtle but important repercussions for BPF, since this means the Go
runtime will call `Close()` on an object's underlying file descriptor if the
object is no longer reachable by the garbage collector. For example, this can
happen if an object is created in a function, but is not returned to the caller.
One type of map, {{ godoc('ProgramArray') }}, is particularly sensitive to this.
More about that in [Program Arrays](#program-arrays).

## Extending Object Lifetime

### Pinning

Aside from file descriptors, BPF provides another method of creating references
to eBPF objects: pinning. This is the concept of associating a file on a virtual
file system (the BPF File System, bpffs for short) with a BPF resource like a
Map, Program or Link. Pins can be organized into arbitrary directory structures,
just like on any other file system.

When the Go process exits, the pin will maintain a reference to the object,
preventing it from being automatically destroyed. In this scenario, removing the
pin using plain `rm` will remove the last reference, causing the kernel to
destroy the object. If you're holding an active object in Go, you can also call
{{ godoc('Map.Unpin') }}, {{ godoc('Program.Unpin') }} or {{
godoc('link/Link.Unpin') }} if the object was previously pinned.

!!! warning
    Pins do **not** persist through a reboot!

A common use case for pinning is sharing eBPF objects between processes. For
example, one could create a Map from Go, pin it, and inspect it using `bpftool
map dump pinned /sys/fs/bpf/my_map`.

### Attaching

Attaching a Program to a hook acts as a reference to a Program, since the kernel
needs to be able to execute the program's instructions at any point.

For legacy reasons, some {{ godoc('link/Link') }} types don't support pinning.
It is generally safe to assume these links will persist beyond the lifetime of
the Go application.

## :warning: Program Arrays

A {{ godoc('ProgramArray') }} is a Map type that holds references to other
Programs. This allows programs to 'tail call' into other programs, useful for
splitting up long and complex programs.

Program Arrays have a unique property: they allow cyclic dependencies to be
created between the Program Array and a Program (e.g. allowing programs to call
into themselves).To avoid ending up with a set of programs loaded into the
kernel that cannot be freed, the kernel maintains a hard rule: **Program Arrays
require at least one open file descriptor or bpffs pin**.

!!! warning
    If all user space/bpffs references are gone, **any tail calls into the array
    will fail**, but the Map itself will remain loaded as long as there are
    programs that use it. This property, combined with interactions with Go's
    garbage collector previously described in [File Descriptors and
    Go](#file-descriptors-and-go), is a great source of bugs.

A few tips to handle this problem correctly:

- Use {{ godoc('CollectionSpec.LoadAndAssign') }}. It will refuse to load the
  CollectionSpec if doing so would result in a Program Array without a userspace
  reference.
- Pin Program Arrays if execution of your eBPF code needs to continue past the
  lifetime of your Go application, e.g. for upgrades or short-lived CLI tools.
- Retain references to the Map at all times in long-running applications. Note
  that `#!go defer m.Close()` makes Go retain a reference until the end of the
  current scope.
