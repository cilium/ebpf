# Maps

eBPF maps are kernel data structures used to exchange data between eBPF programs
and user space, or between multiple eBPF programs. The library provides helpers
to load, access, and manipulate maps defined in ELF objects.

This section describes how to declare maps in C, load them using `bpf2go`, and
interact with them from Go.

## Declaring Maps

Maps are typically declared in the eBPF C source using BTF-style map
definitions.

Example:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

The section name .maps is required for libbpf-compatible loaders.

Map attributes:

type — Map type (e.g. BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY)

max_entries — Maximum number of elements

key — Key type

value — Value type

Loading Maps in Go

The bpf2go tool generates Go types for maps and programs defined in the C
file.

After running go generate, maps become accessible through the generated
objects struct:

objs := bpfObjects{}
if err := loadBpfObjects(&objs, nil); err != nil {
    log.Fatal(err)
}
defer objs.Close()

Maps can then be accessed via fields on objs.

Reading and Writing Map Values
Updating Elements
key := uint32(1)
value := uint64(42)

if err := objs.PacketCount.Put(key, value); err != nil {
    log.Fatalf("updating map: %v", err)
}
Looking Up Elements
var value uint64
if err := objs.PacketCount.Lookup(key, &value); err != nil {
    log.Fatalf("lookup failed: %v", err)
}
Deleting Elements
if err := objs.PacketCount.Delete(key); err != nil {
    log.Fatalf("delete failed: %v", err)
}
Iterating Over Maps

Maps can be iterated using an iterator:

iter := objs.PacketCount.Iterate()

var key uint32
var value uint64

for iter.Next(&key, &value) {
    fmt.Printf("key=%d value=%d\n", key, value)
}

if err := iter.Err(); err != nil {
    log.Fatalf("iteration error: %v", err)
}
Pinning Maps

Maps may be pinned to the BPF filesystem to persist beyond the lifetime of the
process.

if err := objs.PacketCount.Pin("/sys/fs/bpf/packet_count"); err != nil {
    log.Fatalf("pinning failed: %v", err)
}

Pinned maps can later be reopened:

m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/packet_count", nil)
if err != nil {
    log.Fatal(err)
}
Common Pitfalls
Incorrect Key or Value Size

The Go types used must match the C definition exactly. Mismatched sizes result
in runtime errors.

Map Capacity Limits

Attempting to insert more elements than max_entries allows will fail.

Missing BTF Information

Some map features require kernel BTF support. Ensure the target kernel supports
BTF when using advanced features.

Next Steps

See also:

Program loading and attachment

bpf2go usage

Object lifecycle