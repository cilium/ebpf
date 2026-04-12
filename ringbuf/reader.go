package ringbuf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Wraps an eventRing to provide a copy-and-advance read for Reader.
type safeRing struct {
	eventRing
}

func (sr *safeRing) readRecord(rec *Record) error {
	buf := rec.RawSample

	defer func() { sr.advanceTo(sr.pendingPosition()) }()

	err := sr.readRecordUnsafe(rec)
	if err != nil {
		return err
	}

	n := len(rec.RawSample)
	if cap(buf) < n {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	copy(buf, rec.RawSample)
	rec.RawSample = buf

	return nil
}

// Allows reading bpf_ringbuf_output from user space.
type Reader struct {
	readerBase
	safeRing *safeRing
}

// Creates a new BPF ringbuf reader.
func NewReader(ringbufMap *ebpf.Map) (*Reader, error) {
	r := new(Reader)
	if err := initReaderBase(&r.readerBase, ringbufMap); err != nil {
		return nil, err
	}
	r.safeRing = &safeRing{r.ring}
	return r, nil
}

// Read the next record from the BPF ringbuf.
//
// Calling [Close] interrupts the method with [os.ErrClosed]. Calling [Flush]
// makes it return all records currently in the ring buffer, followed by [ErrFlushed].
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and after all records
// have been read from the ring.
//
// See [ReadInto] for a more efficient version of this method.
func (r *Reader) Read() (Record, error) {
	var rec Record
	err := r.ReadInto(&rec)
	return rec, err
}

// ReadInto is like Read except that it allows reusing Record and associated buffers.
func (r *Reader) ReadInto(rec *Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ring == nil {
		return fmt.Errorf("ringbuffer: %w", ErrClosed)
	}

	return r.readWaitLocked(func() error {
		return r.safeRing.readRecord(rec)
	})
}
