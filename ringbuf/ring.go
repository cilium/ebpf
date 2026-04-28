package ringbuf

import (
	"fmt"
	"io"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

// ringReader abstracts reading from a bpf ringbuf.
type ringReader struct {
	prod_pos, cons_pos *atomic.Uintptr

	// Local consumer position to support reading multiple messages from the ring
	// before committing.
	localCons uintptr

	// mask is the range of valid record start offsets, limited to the first half
	// of the double-mapped data pages.
	mask uintptr

	// data contains the double-mapped data pages of the ringbuf.
	data []byte
}

// newRingReader creates a new ringReader with the given producer and consumer
// pointers and data pages.
func newRingReader(cons_ptr, prod_ptr *atomic.Uintptr, data []byte) *ringReader {
	return &ringReader{
		prod_pos:  prod_ptr,
		cons_pos:  cons_ptr,
		localCons: cons_ptr.Load(),
		// cap is always a power of two
		mask: uintptr(cap(data)/2 - 1),
		data: data,
	}
}

// To be able to wrap around data, data pages in ring buffers are mapped twice
// in a single contiguous virtual region. Therefore the returned usable size is
// half the size of the mmaped region.
func (rr *ringReader) size() int {
	return cap(rr.data) / 2
}

// The amount of data available to read in the ring buffer. Only tracks
// committed cursors.
func (rr *ringReader) AvailableBytes() uint64 {
	return uint64(rr.prod_pos.Load() - rr.cons_pos.Load())
}

// commit sets the consumer position in shared kernel memory to the local
// consumer position.
func (rr *ringReader) commit() {
	rr.cons_pos.Store(rr.localCons)
}

// Read a record from an event ring.
func (rr *ringReader) readRecord(rec *Record) error {
	// Read kernel memory once per wakeup to avoid TOCTOU and unnecessary
	// synchronization.
	prod := rr.prod_pos.Load()
	cons := rr.localCons

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
	len := atomic.LoadUint32((*uint32)(unsafe.Pointer(&rr.data[start])))
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
		// discarded, we skip it by just updating the consumer position
		// to the next record.
		rr.localCons = cons
		rr.commit()
		return errDiscard
	}

	if n := header.dataLen(); cap(rec.RawSample) < n {
		rec.RawSample = make([]byte, n)
	} else {
		rec.RawSample = rec.RawSample[:n]
	}

	copy(rec.RawSample, rr.data[start:])
	rec.Remaining = int(prod - cons)

	rr.localCons = cons
	rr.commit()
	return nil
}
