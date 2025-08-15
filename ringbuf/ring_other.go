//go:build !windows

package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

type ringbufEventRing struct {
	prod []byte
	cons []byte
	*ringReader
}

func newRingBufEventRing(mapFD, size int) (*ringbufEventRing, error) {
	cons, err := unix.Mmap(mapFD, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(mapFD, (int64)(os.Getpagesize()), os.Getpagesize()+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("mmap data pages: %w", err)
	}

	cons_pos := (*uintptr)(unsafe.Pointer(&cons[0]))
	prod_pos := (*uintptr)(unsafe.Pointer(&prod[0]))

	ring := &ringbufEventRing{
		prod:       prod,
		cons:       cons,
		ringReader: newRingReader(cons_pos, prod_pos, prod[os.Getpagesize():]),
	}
	runtime.SetFinalizer(ring, (*ringbufEventRing).Close)

	return ring, nil
}

func (ring *ringbufEventRing) Close() error {
	runtime.SetFinalizer(ring, nil)

	prod, cons := ring.prod, ring.cons
	ring.prod, ring.cons = nil, nil

	return errors.Join(
		unix.Munmap(prod),
		unix.Munmap(cons),
	)
}
