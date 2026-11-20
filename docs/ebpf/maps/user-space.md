# Using Maps from User Space

Once a map exists, {{ proj }} exposes it as a {{ godoc('Map') }}. The type
offers the operations you'd expect from a key/value store, plus a few that are
specific to BPF maps. This page covers reading and writing entries, iterating,
batching, per-CPU values and pinning.

For how maps get declared in the first place, see [Declaring
Maps](declaring.md).

## Getting a Map

There are three common ways to obtain a `Map`:

- from a loaded collection, through {{ godoc('Collection.Maps') }}
- injected into a struct by {{ godoc('CollectionSpec.LoadAndAssign') }}
- created directly with {{ godoc('NewMap') }}, without a BPF program

All three return the same type and behave identically. A map obtained from a
collection is owned by that collection: closing the collection closes its maps
unless they are pinned or have another reference.

## Key and value encoding

`Map` methods accept Go values for keys and values and encode them for you. The
encoding follows two rules:

- Values must have a fixed width. Untyped integers are rejected because their
  size is platform dependent; use `uint32`, `uint64` and friends explicitly.
- Structs are encoded using their field layout, so padding matters. Go and C
  definitions must match byte for byte.

{{ go_example('DocMapStruct', title='Using a struct as map key') }}

{{ godoc('MapSpec') }} sizes are expressed in bytes. When a struct is used as a
key, derive the size from the type instead of hard-coding it. Note that
`binary.Size` reports the encoded size, excluding padding, which is what the
encoder produces.

## Reading and writing entries

{{ godoc('Map.Put') }} creates an entry or overwrites an existing one. The
distinction matters for array maps: their elements always exist, so `Put` can
only overwrite an index that is already in range. {{ godoc('Map.Lookup') }}
retrieves a value and returns an error wrapping {{ godoc('ErrKeyNotExist') }}
when the key is absent:

{{ go_example('DocMapPutLookup', title='Writing and reading a single entry') }}

The value passed to `Lookup` must be a pointer to a fixed-width type. The map's
value size and the size of that type are checked at runtime, and a mismatch is
reported as an error rather than silently truncating data.

## Creating versus updating

`Put` always behaves like "create or replace". When the distinction matters,
use {{ godoc('Map.Update') }} with explicit flags:

{{ go_example('DocMapUpdate', title='Conditional update and delete') }}

- {{ godoc('UpdateNoExist') }} fails if the entry already exists.
- {{ godoc('UpdateExist') }} fails if it does not.
- {{ godoc('UpdateAny') }} is the default used by `Put`.

These flags are enforced by the kernel and are atomic with respect to other
writers, which makes them suitable for coordination between processes.

## Iterating

{{ godoc('Map.Iterate') }} returns a {{ godoc('MapIterator') }} that walks every
entry:

{{ go_example('DocMapIterate', title='Iterating over all entries') }}

Iteration is not a snapshot. Deleting keys while iterating may cause the same
key to be visited twice, and iteration can abort if the map changes
concurrently. Always check {{ godoc('MapIterator.Err') }} after the loop;
{{ godoc('MapIterator.Next') }} returning false does not distinguish "done"
from "failed".

Array maps iterate in index order, including indexes that were never written
to. Hash maps have no defined order.

## Batch operations

Kernels 5.6 and later support batch lookups and updates, which amortize the
syscall overhead over many entries:

{{ go_example('DocMapBatch', title='Looking up entries in batches') }}

The returned count is the number of entries written to the output slices. The
call reports {{ godoc('ErrKeyNotExist') }} once the map is exhausted, even when
it also returned entries in the same call. Treat that error as the end marker
rather than a failure.

When the slices fill up before the map is exhausted, pass the cursor to another
call to continue where the previous one stopped.

Batch operations require kernel 5.6 or later; older kernels return an error
instead of falling back silently. Per-CPU array maps only gained batch support
in 5.13, so be prepared to handle that error on older kernels.

## Per-CPU maps

Per-CPU maps keep a separate value for every CPU, which avoids contention on
hot paths. User space still sees a single key, but reads and writes take a slice
with one element per possible CPU:

{{ go_example('DocMapPerCPU', title='Reading per-CPU values') }}

The slice length must equal {{ godoc('MustPossibleCPU') }} exactly. Any other
length is rejected with an error.

## Pinning maps

Pinning gives a map a path in bpffs, keeping it alive after the owning process
exits and making it reachable from other processes:

{{ go_example('DocMapPin', title='Pinning a map and loading it back') }}

{{ godoc('Map.Pin') }} attaches an existing map to a path and replaces the pin
the map already had. Pinning to a path that is already occupied fails; remove
the existing pin first if that is intended.

To have a map pinned automatically at creation time, set
{{ godoc('MapSpec.Pinning') }} and provide a base path through
{{ godoc('MapOptions.PinPath') }}. Unlike `Pin`, this path reuses an existing
map when it is compatible with the spec and fails otherwise.

## Closing

{{ godoc('Map.Close') }} releases the user space file descriptor. The map
itself lives on as long as the kernel has another reason to keep it: a loaded
program that references it, a pin in bpffs, or another process holding a
descriptor.

Closing a map that is still in use by a program is safe; closing it while it is
the only reference destroys the map and its contents.