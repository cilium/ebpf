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
	getRing() []byte
	writeTail()
	Read(p []byte) (int, error)
}

type forwardReader struct{
	meta         *unix.PerfEventMmapPage
	head, tail   uint64
	mask         uint64
	ring         []byte
}

type reverseReader struct{
	meta         *unix.PerfEventMmapPage
	// head is the position where the kernel last wrote data, we only read this
	// field, as we will start reading from this position.
	head uint64
	// read is the last position where we read.
	// When we want to read the whole buffer, we will start from head (i.e. read
	// equals head), then we will continue to read from left to right (i.e.
	// increasing the offset).
	read uint64
	// previousHead is the previous head position.
	// We need this information to avoid reading information we already read
	// between two full reads.
	//
	previousHead uint64
	mask         uint64
	ring         []byte
}

func newRingReader(meta *unix.PerfEventMmapPage, ring []byte, overwritable bool) ringReader {
	if overwritable{
		return &reverseReader{
			meta: meta,
			head: atomic.LoadUint64(&meta.Data_head),
			// For overwritable buffer, we use read as previous read position.
			// Since, we will start to read from head, we initialize read to head.
			read: atomic.LoadUint64(&meta.Data_head),
			mask:         uint64(cap(ring) - 1),
			ring:         ring,
		}
	}

	return &forwardReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.Data_head),
		tail: atomic.LoadUint64(&meta.Data_tail),
		// cap is always a power of two
		mask:         uint64(cap(ring) - 1),
		ring:         ring,
	}
}

func (fr *forwardReader) loadHead() {
	fr.head = atomic.LoadUint64(&fr.meta.Data_head)
}

func (fr *forwardReader) getRing() []byte {
	return fr.ring
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
	rr.previousHead = rr.head
	rr.head = atomic.LoadUint64(&rr.meta.Data_head)
	rr.read = atomic.LoadUint64(&rr.meta.Data_head)
}

func (rr *reverseReader) getRing() []byte {
	return rr.ring
}

func (rr *reverseReader) writeTail() {
	// We do not care about tail for over writable perf buffer.
	// So, this function is noop.
}

func (rr *reverseReader) Read(p []byte) (int, error) {
	read := rr.read

	// This prevents reading data we already processed:
	//
	//    head        previous_head--+     read
	//     |                         |      |
	//     V                         V      V
	// +---+------+----------+-------+------+
	// |   |D....D|C........C|B.....B|A....A|
	// +---+------+----------+-------+------+
	// <--Write from right to left
	//             Read from left to right-->
	if rr.previousHead != 0 && read >= rr.previousHead {
		rr.previousHead = rr.head

		return 0, io.EOF
	}

	// If adding the size to the current consumer position makes us wrap the
	// buffer, it means we already did "one loop" around the buffer.
	// So, the pointed data would not be usable:
	//
	//                                  head
	//                       read----+   |
	//                               |   |
	//                               V   V
	// +---+------+----------+-------+---+--+
	// |..E|D....D|C........C|B.....B|A..|E.|
	// +---+------+----------+-------+---+--+
	if read-rr.head+uint64(len(p)) > rr.mask {
		rr.previousHead = rr.head

		return 0, io.EOF
	}

	size := uint32(len(p))
	previousReadMasked := read & rr.mask
	read += uint64(size)

	// If adding the event size to the current
	// consumer position makes us going from end of the buffer toward the
	// start, we need to copy the rr.ring in two times:
	// 1. First from previous_read until end of the buffer.
	// 2. Second from start of the buffer until read.
	//
	//    read                   previous_read
	//     |                             |
	//     V                             V
	// +---+------+----------+-------+---+--+
	// |..E|D....D|C........C|B.....B|A..|E.|
	// +---+------+----------+-------+---+--+
	// This code snippet was highly inspired by gobpf:
	// https://github.com/iovisor/gobpf/blob/16120a1bf4d4abc1f9cf37fecfb86009a1631b9f/elf/perf.go#L148
	if (read & rr.mask) < previousReadMasked {
		// Compute the number of bytes from the beginning of this sample until
		// the end of the buffer.
		length := uint32(rr.mask + 1 - previousReadMasked)

		// From previousRead until end of the buffer.
		copy(p[0:length-1], rr.ring[previousReadMasked:previousReadMasked+uint64(length)])
		// From beginning of the buffer until read.
		copy(p[length:], rr.ring[0:size-length])
	} else {
		// We are in the "middle" of the buffer, so no worries!
		copy(p, rr.ring[previousReadMasked:previousReadMasked+uint64(size)])
	}

	// We use this field to store the previous read position.
	// So, we know where to start in next call to this function.
	rr.read = read

	return int(size), nil
}
