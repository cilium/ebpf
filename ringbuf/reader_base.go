package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/platform"
)

var (
	ErrClosed = os.ErrClosed
	errEOR    = errors.New("end of ring")
	errBusy   = errors.New("sample not committed yet")
)

type poller interface {
	Wait(deadline time.Time) error
	Flush() error
	Close() error
}

type Record struct {
	RawSample []byte

	// The minimum number of bytes remaining in the ring buffer after this Record has been read.
	Remaining int
}

type readerBase struct {
	poller poller

	// mu protects read/write access to the reader state.
	mu         sync.Mutex
	ring       eventRing
	haveData   bool
	deadline   time.Time
	bufferSize int
	pendingErr error
}

func initReaderBase(b *readerBase, ringbufMap *ebpf.Map) error {
	if ringbufMap.Type() != ebpf.RingBuf && ringbufMap.Type() != ebpf.WindowsRingBuf {
		return fmt.Errorf("invalid Map type: %s", ringbufMap.Type())
	}

	maxEntries := int(ringbufMap.MaxEntries())
	if maxEntries == 0 || (maxEntries&(maxEntries-1)) != 0 {
		return fmt.Errorf("ringbuffer map size %d is zero or not a power of two", maxEntries)
	}

	poller, err := newPoller(ringbufMap.FD())
	if err != nil {
		return err
	}

	ring, err := newRingBufEventRing(ringbufMap.FD(), maxEntries)
	if err != nil {
		poller.Close()
		return fmt.Errorf("failed to create ringbuf ring: %w", err)
	}

	b.poller = poller
	b.ring = ring
	b.bufferSize = ring.size()
	// On Windows, the wait handle is only set when the reader is created,
	// so we miss any wakeups that happened before.
	// Do an opportunistic read to get any pending samples.
	b.haveData = platform.IsWindows
	return nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
func (b *readerBase) Close() error {
	if err := b.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}

	// Acquire the lock. This ensures that Read isn't running.
	b.mu.Lock()
	defer b.mu.Unlock()

	var err error
	if b.ring != nil {
		err = b.ring.Close()
		b.ring = nil
	}

	return err
}

// SetDeadline controls how long Read and ReadInto will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline.
func (b *readerBase) SetDeadline(t time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.deadline = t
}

// BufferSize returns the size in bytes of the ring buffer.
func (b *readerBase) BufferSize() int {
	return b.bufferSize
}

// Flush unblocks Read/ReadInto and successive Read/ReadInto calls will return pending samples at this point,
// until you receive a ErrFlushed error.
func (b *readerBase) Flush() error {
	return b.poller.Flush()
}

// AvailableBytes returns the amount of data available to read in the ring buffer in bytes.
func (b *readerBase) AvailableBytes() int {
	// Don't need to acquire the lock here since the implementation of AvailableBytes
	// performs atomic loads on the producer and consumer positions.
	return int(b.ring.AvailableBytes())
}

// Polls for data and calls read in a loop. Must be called with b.mu held.
func (b *readerBase) readWaitLocked(read func() error) error {
	for {
		if !b.haveData {
			if pe := b.pendingErr; pe != nil {
				b.pendingErr = nil
				return pe
			}

			err := b.poller.Wait(b.deadline)
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrFlushed) {
				// Ignoring this for reading a valid entry after timeout or flush.
				// This can occur if the producer submitted to the ring buffer
				// with BPF_RB_NO_WAKEUP.
				b.pendingErr = err
			} else if err != nil {
				return err
			}
			b.haveData = true
		}

		for {
			err := read()
			// Not using errors.Is which is quite a bit slower
			// For a tight loop it might make a difference
			if err == errBusy {
				continue
			}
			if err == errEOR {
				b.haveData = false
				break
			}
			return err
		}
	}
}
