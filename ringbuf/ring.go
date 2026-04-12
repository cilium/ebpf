package ringbuf

import (
	"fmt"
	"io"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

type eventRing interface {
	size() int
	AvailableBytes() uint64
	readRecordUnsafe(rec *Record) error
	advanceTo(pos uintptr)
	pendingPosition() uintptr
	Close() error
}

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len uint32
	_   uint32 // pg_off, only used by kernel internals
}

const ringbufHeaderSize = int(unsafe.Sizeof(ringbufHeader{}))

func (rh *ringbufHeader) isBusy() bool {
	return rh.Len&sys.BPF_RINGBUF_BUSY_BIT != 0
}

func (rh *ringbufHeader) isDiscard() bool {
	return rh.Len&sys.BPF_RINGBUF_DISCARD_BIT != 0
}

func (rh *ringbufHeader) dataLen() int {
	return int(rh.Len & ^uint32(sys.BPF_RINGBUF_BUSY_BIT|sys.BPF_RINGBUF_DISCARD_BIT))
}

type ringReader struct {
	// These point into mmap'ed memory and must be accessed atomically.
	prod_pos, cons_pos *uintptr
	mask               uintptr
	ring               []byte

	// Logical consumer position tracking deferred advancement.
	// Only valid when hasPending is true.
	pendingCons uintptr
	hasPending  bool
}

func newRingReader(cons_ptr, prod_ptr *uintptr, ring []byte) *ringReader {
	return &ringReader{
		prod_pos: prod_ptr,
		cons_pos: cons_ptr,
		// cap is always a power of two
		mask: uintptr(cap(ring)/2 - 1),
		ring: ring,
	}
}

// To be able to wrap around data, data pages in ring buffers are mapped twice in
// a single contiguous virtual region.
// Therefore the returned usable size is half the size of the mmaped region.
func (rr *ringReader) size() int {
	return cap(rr.ring) / 2
}

// The amount of data available to read in the ring buffer.
func (rr *ringReader) AvailableBytes() uint64 {
	prod := atomic.LoadUintptr(rr.prod_pos)
	cons := atomic.LoadUintptr(rr.cons_pos)
	return uint64(prod - cons)
}

// Reads the next non-discard record from the ring buffer.
//
// Sets rec.RawSample to a slice of the mmap'd ring buffer memory and does
// not advance the consumer position. Call advanceTo to release the space.
func (rr *ringReader) readRecordUnsafe(rec *Record) error {
	prod := atomic.LoadUintptr(rr.prod_pos)

	cons := rr.pendingCons
	if !rr.hasPending {
		cons = atomic.LoadUintptr(rr.cons_pos)
	}

	for {
		if remaining := prod - cons; remaining == 0 {
			return errEOR
		} else if remaining < sys.BPF_RINGBUF_HDR_SZ {
			return fmt.Errorf("read record header: %w", io.ErrUnexpectedEOF)
		}

		// read the len field of the header atomically to ensure a happens before
		// relationship with the xchg in the kernel. Without this we may see len
		// without BPF_RINGBUF_BUSY_BIT before the written data is visible.
		// See https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/ringbuf.c#L484
		start := cons & rr.mask
		len := atomic.LoadUint32((*uint32)((unsafe.Pointer)(&rr.ring[start])))
		header := ringbufHeader{Len: len}

		if header.isBusy() {
			// the next sample in the ring is not committed yet so we
			// exit without storing the reader/consumer position
			// and start again from the same position.
			return errBusy
		}

		cons += sys.BPF_RINGBUF_HDR_SZ

		// Data is always padded to 8 byte alignment.
		dataLenAligned := uintptr(internal.Align(header.dataLen(), 8))
		if remaining := prod - cons; remaining < dataLenAligned {
			return fmt.Errorf("read sample data: %w", io.ErrUnexpectedEOF)
		}

		start = cons & rr.mask
		cons += dataLenAligned

		if header.isDiscard() {
			// when the record header indicates that the data should be
			// discarded, we skip it by just updating the pending position
			// to the next record.
			rr.pendingCons = cons
			rr.hasPending = true
			continue
		}

		n := header.dataLen()
		rec.RawSample = rr.ring[start : start+uintptr(n)]
		rec.Remaining = int(prod - cons)
		rr.pendingCons = cons
		rr.hasPending = true
		return nil
	}
}

// Sets the consumer position to pos, releasing ring buffer space up to that
// point. If pos matches the current pending read cursor, resets the pending
// state so the next read starts from the committed position.
func (rr *ringReader) advanceTo(pos uintptr) {
	atomic.StoreUintptr(rr.cons_pos, pos)
	if rr.hasPending && pos == rr.pendingCons {
		rr.hasPending = false
	}
}

// Returns the current read cursor position. This is the consumer position
// that includes all records read so far (including discards) but not yet
// committed.
func (rr *ringReader) pendingPosition() uintptr {
	if rr.hasPending {
		return rr.pendingCons
	}
	return atomic.LoadUintptr(rr.cons_pos)
}
