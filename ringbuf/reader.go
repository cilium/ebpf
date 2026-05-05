package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/sys"
)

var (
	ErrClosed = os.ErrClosed
	errEOR    = errors.New("end of ring")
	errBusy   = errors.New("sample not committed yet")
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
	AvailableBytes() uint64
	readRecordFunc(func(sample []byte, remaining int, cons uintptr) error) error
	commitRecord(cons uintptr)
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
	haveData   bool
	deadline   time.Time
	bufferSize int
	pendingErr error
}

// NewReader creates a new BPF ringbuf reader.
func NewReader(ringbufMap *ebpf.Map) (*Reader, error) {
	poller, ring, err := newReaderResources(ringbufMap)
	if err != nil {
		return nil, err
	}

	return &Reader{
		poller:     poller,
		ring:       ring,
		bufferSize: ring.size(),
		// On Windows, the wait handle is only set when the reader is created,
		// so we miss any wakeups that happened before.
		// Do an opportunistic read to get any pending samples.
		haveData: platform.IsWindows,
	}, nil
}

func newReaderResources(ringbufMap *ebpf.Map) (poller, eventRing, error) {
	if ringbufMap.Type() != ebpf.RingBuf && ringbufMap.Type() != ebpf.WindowsRingBuf {
		return nil, nil, fmt.Errorf("invalid Map type: %s", ringbufMap.Type())
	}

	maxEntries := int(ringbufMap.MaxEntries())
	if maxEntries == 0 || (maxEntries&(maxEntries-1)) != 0 {
		return nil, nil, fmt.Errorf("ringbuffer map size %d is zero or not a power of two", maxEntries)
	}

	poller, err := newPoller(ringbufMap.FD())
	if err != nil {
		return nil, nil, err
	}

	ring, err := newRingBufEventRing(ringbufMap.FD(), maxEntries)
	if err != nil {
		poller.Close()
		return nil, nil, fmt.Errorf("failed to create ringbuf ring: %w", err)
	}

	return poller, ring, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read and ReadInto.
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
		err = r.ring.Close()
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

	return readWithPoll(r.poller, r.ring, r.deadline, &r.haveData, &r.pendingErr, func() error {
		return r.ring.readRecordFunc(func(sample []byte, remaining int, cons uintptr) error {
			n := len(sample)
			if cap(rec.RawSample) < n {
				rec.RawSample = make([]byte, n)
			} else {
				rec.RawSample = rec.RawSample[:n]
			}

			copy(rec.RawSample, sample)
			rec.Remaining = remaining
			r.ring.commitRecord(cons)
			return nil
		})
	})
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
	// Don't need to acquire the lock here since the implementation of AvailableBytes
	// performs atomic loads on the producer and consumer positions.
	return int(r.ring.AvailableBytes())
}
