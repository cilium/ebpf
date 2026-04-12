package ringbuf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// An opaque token returned by [UnsafeReader.Read].
// Pass it to [UnsafeReader.Commit] to release the corresponding ring buffer space.
type CommitToken struct {
	consPos uintptr
}

type UnsafeRecord struct {
	Record
}

type pendingItem struct {
	consPos   uintptr
	committed bool
}

// Allows zero-copy reading from a BPF ring buffer.
//
// Records returned by [Read] point directly into the memory-mapped ring buffer
// region. The data is valid until the corresponding [CommitToken] is committed
// via [Commit] or [CommitAll]. After committing, the kernel may overwrite the
// underlying memory at any time.
type UnsafeReader struct {
	readerBase
	pending []pendingItem
}

// Creates a new zero-copy BPF ringbuf reader.
func NewUnsafeReader(ringbufMap *ebpf.Map) (*UnsafeReader, error) {
	r := new(UnsafeReader)
	if err := initReaderBase(&r.readerBase, ringbufMap); err != nil {
		return nil, err
	}
	return r, nil
}

// Returns the next record from the BPF ringbuf without copying.
//
// rec.RawSample points directly into the memory-mapped ring buffer region and
// must not be modified. The slice is valid until the returned [CommitToken] is
// passed to [Commit] or [CommitAll].
//
// Calling [Close] interrupts the method with [os.ErrClosed]. Calling [Flush]
// makes it return all records currently in the ring buffer, followed by [ErrFlushed].
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and after all records
// have been read from the ring.
func (r *UnsafeReader) Read(rec *UnsafeRecord) (CommitToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ring == nil {
		return CommitToken{}, fmt.Errorf("ringbuffer: %w", ErrClosed)
	}

	var token CommitToken
	err := r.readWaitLocked(func() error {
		err := r.ring.readRecordUnsafe(&rec.Record)
		if err != nil {
			return err
		}

		pos := r.ring.pendingPosition()
		token = CommitToken{pos}
		r.pending = append(r.pending, pendingItem{consPos: pos})
		return nil
	})
	return token, err
}

// Reads the next record without copying and calls f with the raw sample data.
// The consumer position for this record is advanced automatically after f
// returns (subject to preceding uncommitted records).
//
// The data slice passed to f points into the memory-mapped ring buffer region,
// must not be modified, and is only valid for the duration of the callback.
//
// Calling [Close] interrupts the method with [os.ErrClosed]. Calling [Flush]
// makes it return all records currently in the ring buffer, followed by [ErrFlushed].
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and after all records
// have been read from the ring.
func (r *UnsafeReader) ReadFunc(f func(data []byte)) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ring == nil {
		return fmt.Errorf("ringbuffer: %w", ErrClosed)
	}

	return r.readWaitLocked(func() error {
		var rec Record
		err := r.ring.readRecordUnsafe(&rec)
		if err != nil {
			return err
		}

		f(rec.RawSample)

		pos := r.ring.pendingPosition()
		r.pending = append(r.pending, pendingItem{consPos: pos, committed: true})
		r.advanceContiguous()

		return nil
	})
}

// Releases ring buffer space associated with the given token.
//
// The consumer position is only advanced when all preceding tokens have also
// been committed. For example, if tokens A, B, C were obtained in order and
// B and C are committed first, the consumer position does not advance until A
// is also committed — at which point it advances past C.
//
// The RawSample slice associated with a committed token must not be used
// after this call.
func (r *UnsafeReader) Commit(token CommitToken) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.pending {
		if r.pending[i].consPos == token.consPos {
			r.pending[i].committed = true
			break
		}
	}

	r.advanceContiguous()
}

// Releases all ring buffer space from preceding [Read] calls.
//
// All RawSample slices from previous Read calls are invalid after this call.
// No-op if there are no pending reads.
func (r *UnsafeReader) CommitAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.pending) == 0 || r.ring == nil {
		return
	}

	r.ring.advanceTo(r.pending[len(r.pending)-1].consPos)
	r.pending = r.pending[:0]
}

// Advances the consumer position past all contiguously committed items
// from the front of the pending list.
func (r *UnsafeReader) advanceContiguous() {
	i := 0
	for i < len(r.pending) && r.pending[i].committed {
		i++
	}
	if i == 0 || r.ring == nil {
		return
	}

	r.ring.advanceTo(r.pending[i-1].consPos)

	n := copy(r.pending, r.pending[i:])
	r.pending = r.pending[:n]
}
