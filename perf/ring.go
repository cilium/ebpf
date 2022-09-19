package perf

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

// perfEventRing is a page of metadata followed by
// a variable number of pages which form a ring buffer.
type perfEventRing struct {
	fd   int
	cpu  int
	mmap []byte
	ringReader
}

func newPerfEventRing(cpu, perCPUBuffer, watermark int, overwritable bool) (*perfEventRing, error) {
	if watermark >= perCPUBuffer {
		return nil, errors.New("watermark must be smaller than perCPUBuffer")
	}

	fd, err := createPerfEvent(cpu, watermark, overwritable)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	protections := unix.PROT_READ
	if !overwritable {
		protections |= unix.PROT_WRITE
	}

	mmap, err := unix.Mmap(fd, 0, perfBufferSize(perCPUBuffer), protections, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}

	// This relies on the fact that we allocate an extra metadata page,
	// and that the struct is smaller than an OS page.
	// This use of unsafe.Pointer isn't explicitly sanctioned by the
	// documentation, since a byte is smaller than sampledPerfEvent.
	meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(&mmap[0]))

	ring := &perfEventRing{
		fd:         fd,
		cpu:        cpu,
		mmap:       mmap,
		ringReader: newRingReader(meta, mmap[meta.Data_offset:meta.Data_offset+meta.Data_size], overwritable),
	}
	runtime.SetFinalizer(ring, (*perfEventRing).Close)

	return ring, nil
}

// mmapBufferSize returns a valid mmap buffer size for use with perf_event_open (1+2^n pages)
func perfBufferSize(perCPUBuffer int) int {
	pageSize := os.Getpagesize()

	// Smallest whole number of pages
	nPages := (perCPUBuffer + pageSize - 1) / pageSize

	// Round up to nearest power of two number of pages
	nPages = int(math.Pow(2, math.Ceil(math.Log2(float64(nPages)))))

	// Add one for metadata
	nPages += 1

	return nPages * pageSize
}

func (ring *perfEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Close(ring.fd)
	_ = unix.Munmap(ring.mmap)

	ring.fd = -1
	ring.mmap = nil
}

func createPerfEvent(cpu, watermark int, overwritable bool) (int, error) {
	if watermark == 0 {
		watermark = 1
	}

	bits := unix.PerfBitWatermark
	if overwritable {
		bits |= unix.PerfBitWriteBackward
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        uint64(bits),
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("can't create perf event: %w", err)
	}
	return fd, nil
}

type ringReader interface {
	loadHead()
	size() int
	writeTail()
	Read(p []byte) (int, error)
}

type forwardReader struct {
	meta       *unix.PerfEventMmapPage
	head, tail uint64
	mask       uint64
	ring       []byte
}

type reverseReader struct {
	meta *unix.PerfEventMmapPage
	// head is the position where the kernel last wrote data. updated as we
	// read data out of the ring.
	head uint64
	// tail is the end of the ring buffer. no reads must be made past it.
	tail uint64
	mask uint64
	ring []byte
}

func newRingReader(meta *unix.PerfEventMmapPage, ring []byte, overwritable bool) ringReader {
	if overwritable {
		return &reverseReader{
			meta: meta,
			head: atomic.LoadUint64(&meta.Data_head),
			// For overwritable buffer, we use read as previous read position.
			// Since, we will start to read from head, we initialize read to head.
			tail: atomic.LoadUint64(&meta.Data_head),
			mask: uint64(cap(ring) - 1),
			ring: ring,
		}
	}

	return &forwardReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.Data_head),
		tail: atomic.LoadUint64(&meta.Data_tail),
		// cap is always a power of two
		mask: uint64(cap(ring) - 1),
		ring: ring,
	}
}

func (fr *forwardReader) loadHead() {
	fr.head = atomic.LoadUint64(&fr.meta.Data_head)
}

func (fr *forwardReader) size() int {
	return len(fr.ring)
}

func (fr *forwardReader) writeTail() {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&fr.meta.Data_tail, fr.tail)
}

func (fr *forwardReader) Read(p []byte) (int, error) {
	start := int(fr.tail & fr.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(fr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(fr.head - fr.tail); n > remainder {
		n = remainder
	}

	copy(p, fr.ring[start:start+n])
	fr.tail += uint64(n)

	if fr.tail == fr.head {
		return n, io.EOF
	}

	return n, nil
}

func (rr *reverseReader) loadHead() {
	rr.head = atomic.LoadUint64(&rr.meta.Data_head)
	rr.tail = 0

	if rr.head <= 0-uint64(cap(rr.ring)) {
		// ring has been fully written, only permit at most cap(rr.ring)
		// bytes to be read.
		rr.tail = rr.head + uint64(cap(rr.ring))
	}
}

func (rr *reverseReader) size() int {
	return len(rr.ring)
}

func (rr *reverseReader) writeTail() {
	// We do not care about tail for over writable perf buffer.
	// So, this function is noop.
}

func (rr *reverseReader) Read(p []byte) (int, error) {
	start := int(rr.head & rr.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rr.tail - rr.head); n > remainder {
		n = remainder
	}

	copy(p, rr.ring[start:start+n])
	rr.head += uint64(n)

	if rr.head == rr.tail {
		return n, io.EOF
	}

	return n, nil
}
