//go:build !windows

package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

var _ eventRing = (*mmapEventRing)(nil)

type mmapEventRing struct {
	prod []byte
	cons []byte
	*ringReader
	cleanup runtime.Cleanup
}

func newRingBufEventRing(mapFD, size int) (*mmapEventRing, error) {
	// The kernel lays out the ring buffer as follows:
	//
	// | consumer page | producer page | data pages | double-mapped data pages |
	//
	// Double-mapping the data pages allows for contiguous reads when they wrap
	// around the end of the buffer.
	cons, err := unix.Mmap(mapFD, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap consumer page: %w", err)
	}
	// Consumer position is a uint at the start of the consumer page.
	cons_pos := (*atomic.Uintptr)(unsafe.Pointer(unsafe.SliceData(cons)))

	prod, err := unix.Mmap(mapFD, int64(os.Getpagesize()), os.Getpagesize()+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("mmap data pages: %w", err)
	}
	// Producer position is a uint at the start of the producer page.
	prod_pos := (*atomic.Uintptr)(unsafe.Pointer(unsafe.SliceData(prod)))

	ring := &mmapEventRing{
		prod: prod,
		cons: cons,
		// Data pages start after the first producer page.
		ringReader: newRingReader(cons_pos, prod_pos, prod[os.Getpagesize():]),
	}
	ring.cleanup = runtime.AddCleanup(ring, func(*byte) {
		_ = unix.Munmap(prod)
		_ = unix.Munmap(cons)
	}, nil)

	return ring, nil
}

func (ring *mmapEventRing) close() error {
	ring.cleanup.Stop()

	prod, cons := ring.prod, ring.cons
	ring.prod, ring.cons = nil, nil

	return errors.Join(
		unix.Munmap(prod),
		unix.Munmap(cons),
	)
}
