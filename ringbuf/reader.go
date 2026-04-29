package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

var (
	ErrClosed = os.ErrClosed
	errEOR    = errors.New("end of ring")
)

// poller abstracts platform-specific event notification.
type poller interface {
	Wait(deadline time.Time) error
	Flush() error
	Close() error
}

// eventRing abstracts platform-specific ring buffer memory access.
type eventRing interface {
	size() int
	available() int
	readRecord(rec *Record) error
	close() error
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

// dataLenAligned returns the length of the sample data as specified in the
// header, aligned to an 8 byte boundary.
func (rh *ringbufHeader) dataLenAligned() int {
	return int(internal.Align(rh.dataLen(), 8))
}

type Record struct {
	RawSample []byte

	// The minimum number of bytes remaining in the ring buffer after this Record has been read.
	Remaining int
}

// Reader allows reading bpf_ringbuf_output
// from user space.
type Reader struct {
	poller poller

	// mu protects read/write access to the Reader structure
	mu         sync.Mutex
	ring       eventRing
	deadline   time.Time
	bufferSize int
	drainErr   error
}

// NewReader creates a new BPF ringbuf reader.
func NewReader(m *ebpf.Map) (*Reader, error) {
	if m.Type() != ebpf.RingBuf && m.Type() != ebpf.WindowsRingBuf {
		return nil, fmt.Errorf("invalid Map type: %s", m.Type())
	}

	maxEntries := int(m.MaxEntries())
	if maxEntries == 0 || !internal.IsPow(maxEntries) {
		return nil, fmt.Errorf("ringbuffer map size %d is zero or not a power of two", maxEntries)
	}

	poller, err := newPoller(m.FD())
	if err != nil {
		return nil, err
	}

	ring, err := newRingBufEventRing(m.FD(), maxEntries)
	if err != nil {
		poller.Close()
		return nil, fmt.Errorf("failed to create ringbuf ring: %w", err)
	}

	return &Reader{
		poller:     poller,
		ring:       ring,
		bufferSize: ring.size(),
	}, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
func (r *Reader) Close() error {
	if err := r.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}

	// Acquire the lock. This ensures that Read isn't running.
	r.mu.Lock()
	defer r.mu.Unlock()

	var err error
	if r.ring != nil {
		err = r.ring.close()
		r.ring = nil
	}

	return err
}

// SetDeadline controls how long Read and ReadInto will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline.
func (r *Reader) SetDeadline(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.deadline = t
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

	for {
		// On Windows, the wait handle is only set when the reader is created, so we
		// miss any wakeups that happened before. Do an opportunistic read to get
		// any pending samples.
		err := r.ring.readRecord(rec)
		if err == nil {
			return nil
		}

		// Avoid [errors.Is] for performance reasons.
		if err != errEOR {
			// Bubble up unrecoverable errors to the caller.
			return err
		}

		// Ring is empty at this point.

		// Flush any pending drain error from previous call or iteration.
		if err := r.drainErr; err != nil {
			r.drainErr = nil
			return err
		}

		err = r.poller.Wait(r.deadline)
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrFlushed) {
			// The poller was interrupted, but there may still be samples in the
			// ring (e.g. one submitted with BPF_RB_NO_WAKEUP). Store the error
			// to be able return it after we've drained the ring.
			r.drainErr = err

			continue
		}

		if err != nil {
			return err
		}
	}
}

// BufferSize returns the size in bytes of the ring buffer
func (r *Reader) BufferSize() int {
	return r.bufferSize
}

// Flush unblocks Read/ReadInto and successive Read/ReadInto calls will return pending samples at this point,
// until you receive a ErrFlushed error.
func (r *Reader) Flush() error {
	return r.poller.Flush()
}

// AvailableBytes returns the amount of data available to read in the ring buffer in bytes.
func (r *Reader) AvailableBytes() int {
	return r.ring.available()
}
