package ringbuf

import (
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
	"unsafe"

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
func (rr *ringReader) available() int {
	return int(rr.prod_pos.Load() - rr.cons_pos.Load())
}

// commit sets the consumer position in shared kernel memory to the local
// consumer position.
func (rr *ringReader) commit() {
	rr.cons_pos.Store(rr.localCons)
}

// readSample returns the next sample from the ring buffer. data contains the
// sample's bytes, remain is the remaining number of bytes in the buffer after
// this sample.
//
// Returns [errEOR] if the end of the ring is reached. Any other errors indicate
// an integrity issue with the ring and are unrecoverable, meaning the ring
// should not be used further.
//
// If data and err are nil, the sample was discarded by the producer.
//
// [ringReader.commit] must be called to advance the consumer position after
// every nil error, even if data is nil.
func (rr *ringReader) readSample() (data []byte, remain int, err error) {
	// Read kernel memory once per wakeup to avoid TOCTOU and unnecessary
	// synchronization.
	prod := rr.prod_pos.Load()
	cons := rr.localCons

	if remaining := prod - cons; remaining == 0 {
		return nil, 0, errEOR
	} else if remaining < sys.BPF_RINGBUF_HDR_SZ {
		return nil, 0, fmt.Errorf("read record header: %w", io.ErrUnexpectedEOF)
	}

	// read the len field of the header atomically to ensure a happens before
	// relationship with the xchg in the kernel. Without this we may see len
	// without BPF_RINGBUF_BUSY_BIT before the written data is visible.
	// See https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/ringbuf.c#L484
	start := cons & rr.mask
	header := ringbufHeader{}

retry:
	header.Len = atomic.LoadUint32((*uint32)(unsafe.Pointer(&rr.data[start])))
	if header.isBusy() {
		// Sample has not been committed by the bpf program yet but should be
		// soon. Busypoll without advancing the consumer position.

		// Yield the OS thread to give other goroutines a chance to run. The bpf
		// side is copying memory into the sample.
		runtime.Gosched()

		goto retry
	}

	cons += sys.BPF_RINGBUF_HDR_SZ

	aligned := uintptr(header.dataLenAligned())
	if remaining := prod - cons; remaining < aligned {
		return nil, 0, fmt.Errorf("read sample data: %w", io.ErrUnexpectedEOF)
	}

	start = cons & rr.mask
	cons += aligned

	rr.localCons = cons

	remain = int(prod - cons)
	data = rr.data[start : start+uintptr(header.dataLen())]

	if header.isDiscard() {
		// Ringbuf space was reserved but then discarded. The consumer needs to
		// advance, but the sample data should not be returned.
		return nil, remain, nil
	}

	return data, remain, nil
}
