package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

// Memory is the building block for accessing the memory of specific bpf map
// types (Array and Arena at the time of writing) without going through the bpf
// syscall interface.
//
// Given the fd of a bpf map created with the BPF_F_MMAPABLE flag, a shared
// 'file'-based memory-mapped region can be allocated in the process' address
// space, exposing the bpf map's memory by simply accessing a memory location.
//
// Since Go is a garbage-collected language, this complicates things a bit. The
// burden of managing memory lifecycle should never be placed on the caller.
// With the additional requirement of carving out many small objects from this
// memory corresponding to global variables declared in the BPF C program, we
// want to lean on the runtime and GC as much as possible while making sure the
// Go programs remain memory-safe.
//
// This led to a solution that requests regular Go heap memory by allocating a
// slice, allowing the runtime to track any pointers to the slice's backing
// memory. Re-slicing is a core feature of the language, and any kind of pointer
// into a the backing array is sufficient to keep it alive.
//
// Then, before returning the Memory to the caller, a finalizer is set on the
// backing array, making sure the bpf map's memory is unmapped from the heap
// before releasing the backing array to the runtime for reallocation.
//
// Putting the finalizer on the backing array was a conscious decision to avoid
// having to maintain a reference to the Memory at all times, which is hard to
// guarantee if the actual access is done through another object, e.g. a
// sync.Atomic synthesized around a slice of the backing array.
//
// In the current implementation, accessing a Memory (or any derived pointers)
// is guaranteed to access bpf map memory. When all references are gone, the
// allocation's finalizer will run and unmap the bpf map's memory.

//go:linkname heapObjectsCanMove runtime.heapObjectsCanMove
func heapObjectsCanMove() bool

var ErrReadOnly = errors.New("resource is read-only")

// Memory implements accessing a Map's memory without making any syscalls.
// Pay attention to the difference between Go and C struct alignment rules. Use
// [structs.HostLayout] on supported Go versions to help with alignment.
//
// Note on memory coherence: avoid using packed structs in memory shared between
// user space and eBPF C programs. This drops a struct's memory alignment to 1,
// forcing the compiler to use single-byte loads and stores for field accesses.
// This may lead to partially-written data to be observed from user space.
//
// On most architectures, the memmove implementation used by Go's copy() will
// access data in word-sized chunks. If paired with a matching access pattern on
// the eBPF C side (and if using default memory alignment), accessing shared
// memory without atomics or other synchronization primitives should be sound
// for individual values. For accesses beyond a single value, the usual
// concurrent programming rules apply.
type Memory struct {
	b  []byte
	ro bool
}

func newMemory(fd, size int, ro bool) (*Memory, error) {
	// Some architectures need the size to be page-aligned.
	if internal.Align(size, os.Getpagesize()) != size {
		return nil, fmt.Errorf("memory: must be a multiple of page size (requested %d bytes)", size)
	}

	// Allocate a page-aligned span of memory on the Go heap.
	alloc, err := allocate(size)
	if err != nil {
		return nil, fmt.Errorf("allocating memory: %w", err)
	}

	flags := unix.PROT_READ | unix.PROT_WRITE
	if ro {
		flags = unix.PROT_READ
	}

	// Map the bpf map memory over a page-aligned allocation on the Go heap.
	if err := mapmap(fd, alloc, size, flags); err != nil {
		return nil, fmt.Errorf("mapping memory: %w", err)
	}

	mm := &Memory{
		unsafe.Slice((*byte)(alloc), size),
		ro,
	}

	return mm, nil
}

// allocate returns a pointer to a page-aligned section of memory on the Go
// heap, managed by the runtime.
func allocate(size int) (unsafe.Pointer, error) {
	// Memory-mapping over a piece of the Go heap is unsafe when the GC can
	// randomly decide to move objects around, in which case the mapped region
	// will not move along with it.
	if heapObjectsCanMove() {
		return nil, errors.New("this Go runtime has a moving garbage collector")
	}

	if size == 0 {
		return nil, errors.New("size must be greater than 0")
	}

	// Request at least two pages of memory from the runtime to ensure we can
	// align the requested allocation to a page boundary. This is needed for
	// MAP_FIXED and makes sure we don't mmap over some other allocation on the Go
	// heap.
	size = internal.Align(size+os.Getpagesize(), os.Getpagesize())

	// Allocate a new slice and store a pointer to its backing array.
	alloc := unsafe.Pointer(unsafe.SliceData(make([]byte, size)))

	// Align the pointer to a page boundary within the allocation. This may
	// alias the initial pointer if it was already page-aligned.
	aligned := unsafe.Pointer(internal.Align(uintptr(alloc), uintptr(os.Getpagesize())))
	runtime.KeepAlive(alloc)

	// Return an aligned pointer into the backing array, losing the original
	// reference. The runtime.SetFinalizer docs specify that its argument 'must be
	// a pointer to an object, complit or local var', but this is still somewhat
	// vague and not enforced by the current implementation.
	//
	// Currently, finalizers can be set and triggered from any address within a
	// heap allocation, even individual struct fields or arbitrary offsets within
	// a slice. In this case, finalizers set on struct fields or slice offsets
	// will only run when the whole struct or backing array are collected. The
	// accepted runtime.AddCleanup proposal makes this behaviour more explicit and
	// is set to deprecate runtime.SetFinalizer.
	//
	// Alternatively, we'd have to track the original allocation and the aligned
	// pointer separately, which severely complicates finalizer setup and makes it
	// prone to human error. For now, just bump the pointer and treat it as the
	// new and only reference to the backing array.
	return aligned, nil
}

// mapmap memory-maps the given file descriptor at the given address and sets a
// finalizer on addr to unmap it when it's no longer reachable.
func mapmap(fd int, addr unsafe.Pointer, size, flags int) error {
	// Map the bpf map memory over the Go heap. This will result in the following
	// mmap layout in the process' address space (0xc000000000 is a span of Go
	// heap), visualized using pmap:
	//
	// Address           Kbytes     RSS   Dirty Mode  Mapping
	// 000000c000000000    1824     864     864 rw--- [ anon ]
	// 000000c0001c8000       4       4       4 rw-s- [ anon ]
	// 000000c0001c9000    2268      16      16 rw--- [ anon ]
	//
	// This will break up the Go heap, but as long as the runtime doesn't try to
	// move our allocation around, this is safe for as long as we hold a reference
	// to our allocated object.
	//
	// Use MAP_SHARED to make sure the kernel sees any writes we do, and MAP_FIXED
	// to ensure the mapping starts exactly at the address we requested. If alloc
	// isn't page-aligned, the mapping operation will fail.
	if _, err := unix.MmapPtr(fd, 0, addr, uintptr(size),
		flags, unix.MAP_SHARED|unix.MAP_FIXED); err != nil {
		return fmt.Errorf("setting up memory-mapped region: %w", err)
	}

	// Set a finalizer on the heap allocation to undo the mapping before the span
	// is collected and reused by the runtime. This has a few reasons:
	//
	//  - Avoid leaking memory/mappings.
	//  - Future writes to this memory should never clobber a bpf map's contents.
	//  - Some bpf maps are mapped read-only, causing a segfault if the runtime
	//    reallocates and zeroes the span later.
	runtime.SetFinalizer((*byte)(addr), unmap(size))

	return nil
}

// unmap returns a function that takes a pointer to a memory-mapped region on
// the Go heap. The function undoes any mappings and discards the span's
// contents.
//
// Used as a finalizer in [newMemory], split off into a separate function for
// testing and to avoid accidentally closing over the unsafe.Pointer to the
// memory region, which would cause a cyclical reference.
//
// The resulting function panics if the mmap operation returns an error, since
// it would mean the integrity of the Go heap is compromised.
func unmap(size int) func(*byte) {
	return func(a *byte) {
		// Create another mapping at the same address to undo the original mapping.
		// This will cause the kernel to repair the slab since we're using the same
		// protection mode and flags as the original mapping for the Go heap.
		//
		// Address           Kbytes     RSS   Dirty Mode  Mapping
		// 000000c000000000    4096     884     884 rw--- [ anon ]
		//
		// Using munmap here would leave an unmapped hole in the heap, compromising
		// its integrity.
		//
		// MmapPtr allocates another unsafe.Pointer at the same address. Even though
		// we discard it here, it may temporarily resurrect the backing array and
		// delay its collection to the next GC cycle.
		_, err := unix.MmapPtr(-1, 0, unsafe.Pointer(a), uintptr(size),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_FIXED|unix.MAP_ANONYMOUS)
		if err != nil {
			panic(fmt.Errorf("undoing bpf map memory mapping: %w", err))
		}
	}
}

// Size returns the size of the memory-mapped region in bytes.
func (mm *Memory) Size() int {
	return len(mm.b)
}

// Readonly returns true if the memory-mapped region is read-only.
func (mm *Memory) Readonly() bool {
	return mm.ro
}

// ReadAt implements [io.ReaderAt]. Useful for creating a new [io.OffsetWriter].
//
// See [Memory] for details around memory coherence.
func (mm *Memory) ReadAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}

	if p == nil {
		return 0, fmt.Errorf("input buffer p is nil")
	}

	if off < 0 || off >= int64(len(mm.b)) {
		return 0, fmt.Errorf("read offset out of range")
	}

	n := copy(p, mm.b[off:])
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

// WriteAt implements [io.WriterAt]. Useful for creating a new
// [io.SectionReader].
//
// See [Memory] for details around memory coherence.
func (mm *Memory) WriteAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}
	if mm.ro {
		return 0, fmt.Errorf("memory-mapped region not writable: %w", ErrReadOnly)
	}

	if p == nil {
		return 0, fmt.Errorf("output buffer p is nil")
	}

	if off < 0 || off >= int64(len(mm.b)) {
		return 0, fmt.Errorf("write offset out of range")
	}

	n := copy(mm.b[off:], p)
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}
