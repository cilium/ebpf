package ringbuf

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
)

type ringbufEventRing struct {
	mapFd            *sys.FD
	cons, prod, data *uint8
	*ringReader
}

func newRingBufEventRing(mapFD, size int) (*ringbufEventRing, error) {
	dupFd, err := efw.EbpfDuplicateFd(mapFD)
	if err != nil {
		return nil, fmt.Errorf("duplicate map fd: %w", err)
	}

	fd, err := sys.NewFD(dupFd)
	if err != nil {
		_ = efw.EbpfCloseFd(dupFd)
		return nil, err
	}

	consPtr, prodPtr, dataPtr, dataLen, err := efw.EbpfRingBufferMapMapBuffer(dupFd)
	if err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("map consumer page: %w", err)
	}

	if dataLen != efw.Size(size) {
		_ = fd.Close()
		return nil, fmt.Errorf("map data length mismatch: %d != %d", dataLen, size)
	}

	// consPtr and prodPtr are guaranteed to be page size aligned.
	consPos := (*uintptr)(unsafe.Pointer(consPtr))
	prodPos := (*uintptr)(unsafe.Pointer(prodPtr))
	data := unsafe.Slice(dataPtr, dataLen*2)

	ring := &ringbufEventRing{
		mapFd:      fd,
		cons:       consPtr,
		prod:       prodPtr,
		data:       dataPtr,
		ringReader: newRingReader(consPos, prodPos, data),
	}
	runtime.SetFinalizer(ring, (*ringbufEventRing).Close)

	return ring, nil
}

func (ring *ringbufEventRing) Close() error {
	runtime.SetFinalizer(ring, nil)

	return errors.Join(
		efw.EbpfRingBufferMapUnmapBuffer(ring.mapFd.Int(), ring.cons, ring.prod, ring.data),
		ring.mapFd.Close(),
	)
}
