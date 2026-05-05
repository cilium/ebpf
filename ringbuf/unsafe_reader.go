package ringbuf

import (
	"errors"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/platform"
)

// UnsafeReader allows reading ringbuf records without copying sample data.
//
// UnsafeReader is not safe for concurrent use.
//
// Samples returned from Read / ReadInto remain valid only until Commit is called.
// Samples passed to ReadFunc are valid only during callback execution.
type UnsafeReader struct {
	poller poller
	ring   eventRing

	haveData   bool
	deadline   time.Time
	bufferSize int
	pendingErr error

	pendingCons uintptr
	pendingRead bool
}

// NewUnsafeReader creates a new BPF ringbuf reader exposing zero-copy APIs.
func NewUnsafeReader(ringbufMap *ebpf.Map) (*UnsafeReader, error) {
	poller, ring, err := newReaderResources(ringbufMap)
	if err != nil {
		return nil, err
	}

	return &UnsafeReader{
		poller:     poller,
		ring:       ring,
		bufferSize: ring.size(),
		// On Windows, the wait handle is only set when the reader is created,
		// so we miss any wakeups that happened before.
		// Do an opportunistic read to get any pending samples.
		haveData: platform.IsWindows,
	}, nil
}

// SetDeadline controls how long Read, ReadInto and ReadFunc will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline.
func (r *UnsafeReader) SetDeadline(t time.Time) {
	r.deadline = t
}

// Read the next record from the BPF ringbuf.
//
// Calling [UnsafeReader.Close] interrupts the method with [os.ErrClosed].
// Calling [UnsafeReader.Flush] makes it return all records currently in the ring
// buffer, followed by [ErrFlushed].
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and after all records
// have been read from the ring.
//
// The returned sample aliases the ring buffer and remains valid until Commit is
// called.
func (r *UnsafeReader) Read() (Record, error) {
	var rec Record
	err := r.ReadInto(&rec)
	return rec, err
}

// ReadInto is like Read except that it allows reusing Record.
//
// ReadInto does not copy sample bytes. rec.RawSample aliases ring buffer memory
// and remains valid until Commit is called.
func (r *UnsafeReader) ReadInto(rec *Record) error {
	if r.pendingRead {
		return errors.New("ringbuffer: previous record must be committed")
	}

	return readWithPoll(r.poller, r.ring, r.deadline, &r.haveData, &r.pendingErr, func() error {
		return r.ring.readRecordFunc(func(sample []byte, remaining int, cons uintptr) error {
			rec.RawSample = sample
			rec.Remaining = remaining
			r.pendingRead = true
			r.pendingCons = cons
			return nil
		})
	})
}

// ReadFunc reads and processes one record via callback.
//
// The callback receives a sample view into ring buffer memory, which is valid
// only for the duration of the callback. The consumed record is committed even
// if the callback returns an error.
//
// The returned value is the minimum bytes remaining in the ring buffer after
// this record has been consumed.
func (r *UnsafeReader) ReadFunc(f func(sample []byte, remaining int) error) (int, error) {
	if r.pendingRead {
		return 0, errors.New("ringbuffer: previous record must be committed")
	}

	var (
		rec Record
		err error
	)

	err = readWithPoll(r.poller, r.ring, r.deadline, &r.haveData, &r.pendingErr, func() error {
		return r.ring.readRecordFunc(func(sample []byte, remaining int, cons uintptr) error {
			defer r.ring.commitRecord(cons)

			callErr := f(sample, remaining)
			rec.Remaining = remaining
			return callErr
		})
	})
	return rec.Remaining, err
}

// Commit advances the reader past the most recently read record.
func (r *UnsafeReader) Commit() error {
	if !r.pendingRead {
		return errors.New("ringbuffer: no pending record to commit")
	}

	r.ring.commitRecord(r.pendingCons)
	r.pendingCons = 0
	r.pendingRead = false
	return nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read, ReadInto and ReadFunc.
func (r *UnsafeReader) Close() error {
	if err := r.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}

	var err error
	if r.ring != nil {
		err = r.ring.Close()
		r.ring = nil
	}

	return err
}

// BufferSize returns the size in bytes of the ring buffer.
func (r *UnsafeReader) BufferSize() int {
	return r.bufferSize
}

// Flush unblocks Read/ReadInto/ReadFunc and successive Read/ReadInto/ReadFunc calls return pending
// samples at this point, until ErrFlushed is returned.
func (r *UnsafeReader) Flush() error {
	return r.poller.Flush()
}

// AvailableBytes returns the amount of data available to read in the ring
// buffer in bytes.
func (r *UnsafeReader) AvailableBytes() int {
	return int(r.ring.AvailableBytes())
}
