package ringbuf

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

type ringbufEventRing struct {
	fd   int
	prod []byte
	cons []byte
	*ringReader
}

func newRingBufEventRing(mapFD, size int) (*ringbufEventRing, error) {
	cons, err := unix.Mmap(mapFD, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(mapFD)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}

	prod, err := unix.Mmap(mapFD, (int64)(os.Getpagesize()), os.Getpagesize()+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		unix.Close(mapFD)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}

	cons_pos := (*uint64)(unsafe.Pointer(&cons[0]))
	prod_pos := (*uint64)(unsafe.Pointer(&prod[0]))

	ring := &ringbufEventRing{
		fd:         mapFD,
		prod:       prod,
		cons:       cons,
		ringReader: newRingReader(cons_pos, prod_pos, prod[os.Getpagesize():]),
	}
	runtime.SetFinalizer(ring, (*ringbufEventRing).Close)

	return ring, nil
}

func (ring *ringbufEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Close(ring.fd)
	_ = unix.Munmap(ring.prod)
	_ = unix.Munmap(ring.cons)

	ring.fd = -1
	ring.prod = nil
	ring.cons = nil
}

type ringReader struct {
	prod_pos, cons_pos *uint64
	cons               uint64
	mask               uint64
	ring               []byte
}

func newRingReader(cons_ptr, prod_ptr *uint64, ring []byte) *ringReader {
	return &ringReader{
		prod_pos: prod_ptr,
		cons_pos: cons_ptr,
		cons:     atomic.LoadUint64(cons_ptr),
		// cap is always a power of two
		mask: uint64(cap(ring)/2 - 1),
		ring: ring,
	}
}

func (rr *ringReader) loadConsumer() {
	rr.cons = atomic.LoadUint64(rr.cons_pos)
}

func (rr *ringReader) storeConsumer(offset uint64) {
	atomic.StoreUint64(rr.cons_pos, rr.cons+offset)
}

func (rr *ringReader) Read(p []byte) (int, error) {
	start := int(rr.cons & rr.mask)

	prod := atomic.LoadUint64(rr.prod_pos)
	n := len(p)

	// Truncate if there isn't enough data
	if remainder := int(prod - rr.cons); n > remainder {
		n = remainder
	}
	copy(p, rr.ring[start:start+n])
	rr.cons += uint64(n)

	if prod == rr.cons {
		return n, io.EOF
	}

	return n, nil
}
