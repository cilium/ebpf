# Declaring Maps

Maps are how an eBPF program stores data that outlives a single invocation.
They are created by user space, handed to the kernel, and shared between BPF
programs and the application that loaded them. A map can also be read and
written from user space while a program is running, which makes it the usual
way to exchange data between the two.

{{ proj }} creates maps from the definitions in an eBPF ELF, or from a
{{ godoc('MapSpec') }} assembled by hand. This page covers declaring maps in
eBPF C and how those declarations surface in Go. For operating on maps once
they exist, see [Using Maps from User Space](user-space.md).

## Declaring maps in eBPF C

Modern eBPF C uses BTF-style definitions. A map is a global variable placed in
the `.maps` ELF section:

{{ c_example('maps_declare', title='Declaring a hash map in eBPF C') }}

The `__uint`, `__type` and `SEC` macros come from libbpf's
`<bpf/bpf_helpers.h>`. The definition has three essential parts:

- `type` selects the {{ godoc('MapType') }}, for example
  `BPF_MAP_TYPE_HASH`.
- `key` and `value` declare the C types of the map's keys and values. BTF
  records their layout, which {{ proj }} uses to decode entries into Go
  values.
- `max_entries` bounds the number of elements the map can hold.

The map's name is taken from the C variable, so `packets` above shows up as
`"packets"` in {{ godoc('CollectionSpec.Maps') }}. The kernel limits map names
to 15 characters and truncates anything longer, so keep names short.

!!! note ""
    Individual map types accept additional attributes, such as `map_flags`,
    `numa_node` or `inner_map`. Refer to `man bpf` or the [bpf man
    pages](https://man7.org/linux/man-pages/man2/bpf.2.html) for the full list.

### Using a map from a program

A map declared this way is referenced by taking its address, just like any
other global variable:

{{ c_example('maps_program', title='Looking up an entry from a BPF program') }}

{{ proj }} rewrites the reference into a map file descriptor while loading
the object. This also means the map must be declared before any program that
references it, or in a header included by both.

### Common map types

The right map type depends on the access pattern and on what the kernel
supports for concurrent access:

| Map type              | Characteristics                                      |
|:----------------------|:-----------------------------------------------------|
| `BPF_MAP_TYPE_HASH`   | Unordered key/value store, entries allocated on demand |
| `BPF_MAP_TYPE_ARRAY`  | Fixed-size, preallocated and zero-initialized        |
| `BPF_MAP_TYPE_PERCPU_HASH` | One value per CPU, avoiding contention          |
| `BPF_MAP_TYPE_LRU_HASH` | Hash map that evicts the least recently used entry |
| `BPF_MAP_TYPE_LPM_TRIE` | Longest-prefix match, used for CIDR and route lookups |
| `BPF_MAP_TYPE_QUEUE`  | FIFO queue with a fixed maximum size                 |
| `BPF_MAP_TYPE_RINGBUF` | Multi-producer, single-consumer ring buffer for events |
| `BPF_MAP_TYPE_PROG_ARRAY` | References to other programs, used for tail calls |

Array maps trade flexibility for speed: every element exists from the moment
the map is created, so a lookup with a valid index cannot fail. Hash-type maps
allocate entries on demand, so a lookup for a missing key returns `ENOENT`.

## Legacy map definitions

Programs written before BTF-style definitions became the norm use a fixed-width
struct in a `maps` section:

{{ c_example('maps_legacy', title='Legacy map definition using struct bpf_map_def') }}

This format is deprecated. The struct cannot express newer attributes, and
libbpf has removed it from its headers. {{ proj }} still parses it so that older
objects keep loading, but new code should use BTF-style definitions. If a map
definition is larger than `struct bpf_map_def`, the trailing bytes end up in
{{ godoc('MapSpec.Extra') }} and must be cleared before the map can be
instantiated.

!!! warning ""
    Mixing the two styles in one object is not supported. Pick one and use it
    consistently across the program.

## Inspecting declared maps from Go

Loading an ELF produces a {{ godoc('CollectionSpec') }} whose
{{ godoc('CollectionSpec.Maps') }} field holds one {{ godoc('MapSpec') }} per
declaration. The field is keyed by the C variable name:

{{ go_example('DocMapSpec', title='Enumerating maps declared in an ELF') }}

The example loads `maps.o`, the object that `bpf2go` produces from `maps.c` in
the examples directory.

Every `MapSpec` mirrors the C definition. `Type`, `KeySize`, `ValueSize` and
`MaxEntries` come straight from it, while `Key` and `Value` hold the
corresponding BTF types. The latter are only populated when the object was
built with BTF, typically by passing `-g` to `clang`.

A `MapSpec` can be modified before it is loaded. Setting
{{ godoc('MapSpec.Contents') }} seeds the map with initial entries, and
adjusting `MaxEntries` changes the map's capacity. Changes to a spec have no
effect once it has been loaded, since the kernel has already created the map.

## Creating maps without a BPF program

Not every map needs a program. Daemons sometimes create a map, pin it, and let
unrelated processes populate it. In that case, build a `MapSpec` directly and
call {{ godoc('NewMap') }}:

{{ go_example('DocNewMap', title='Creating a map from a hand-written MapSpec') }}

`NewMap` creates the map in the kernel immediately, unlike loading a collection,
where map creation happens as part of the load. The returned {{ godoc('Map') }}
must be closed when no longer needed. See [Using Maps from User
Space](user-space.md) for the operations available on it.