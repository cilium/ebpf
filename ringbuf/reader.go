package ringbuf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	errClosed = errors.New("perf reader was closed")
	errEOR    = errors.New("end of ring")
	errBusy   = errors.New("sample not committed yet")
)

func addToEpoll(epollfd, fd int) error {

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	}

	if err := unix.EpollCtl(epollfd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		return fmt.Errorf("can't add fd to epoll: %v", err)
	}
	return nil
}

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len   uint32
	PgOff uint32
}

type Record struct {
	RawSample []byte
}

// NB: Has to be preceded by a call to ring.loadHead.
func readRecordFromRing(ring *ringbufEventRing) (Record, error) {
	defer ring.storeConsumer()
	ring.loadConsumer()
	return readRecord(ring)
}

func readRecord(rd io.Reader) (Record, error) {
	var header ringbufHeader
	err := binary.Read(rd, internal.NativeEndian, &header)
	if err == io.EOF {
		return Record{}, errEOR
	}

	if err != nil {
		return Record{}, fmt.Errorf("can't read event header: %v", err)
	}

	//TODO(mythi): add test cases for busy and discard
	if header.Len&unix.BPF_RINGBUF_BUSY_BIT != 0 {
		return Record{}, errBusy
	}

	if header.Len&unix.BPF_RINGBUF_DISCARD_BIT == 0 {
		/* read up to 8 byte alignment */
		data := make([]byte, (header.Len+7)/8*8)
		if _, err := io.ReadFull(rd, data); err != nil {
			return Record{}, fmt.Errorf("can't read sample: %v", err)
		}
		return Record{RawSample: data[:header.Len]}, err
	}

	return Record{}, err
}

// Reader allows reading bpf_ringbuf_output
// from user space.
type Reader struct {
	// mu protects read/write access to the Reader structure
	mu sync.Mutex

	//TODO(mythi): allow reading from multiple maps
	array *ebpf.Map
	mapFd int
	rings []*ringbufEventRing

	epollFd     int
	epollEvents []unix.EpollEvent
	epollRings  []*ringbufEventRing
	// Eventfds for closing
	closeFd int
	// Ensure we only close once
	closeOnce sync.Once
}

// NewReader creates a new reader with default options.
func NewReader(array *ebpf.Map) (*Reader, error) {
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("can't create epoll fd: %v", err)
	}

	var (
		fds        = []int{epollFd}
		maxEntries = int(array.MaxEntries())
		rings      = make([]*ringbufEventRing, 0, 1)
	)

	defer func() {
		if err != nil {
			for _, fd := range fds {
				unix.Close(fd)
			}
			for _, ring := range rings {
				if ring != nil {
					ring.Close()
				}
			}
		}
	}()

	ring, err := newRingBufEventRing(array.FD(), maxEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf ring: %v", err)
	}

	rings = append(rings, ring)

	if err := addToEpoll(epollFd, ring.fd); err != nil {
		return nil, err
	}

	closeFd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	fds = append(fds, closeFd)

	if err := addToEpoll(epollFd, closeFd); err != nil {
		return nil, err
	}

	pr := &Reader{
		rings:   rings,
		array:   array,
		mapFd:   array.FD(),
		epollFd: epollFd,
		// Allocate extra event for closeFd
		epollEvents: make([]unix.EpollEvent, len(rings)+1),
		epollRings:  make([]*ringbufEventRing, 0, len(rings)),
		closeFd:     closeFd,
	}
	runtime.SetFinalizer(pr, (*Reader).Close)
	return pr, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
func (pr *Reader) Close() error {
	var err error
	pr.closeOnce.Do(func() {
		runtime.SetFinalizer(pr, nil)

		// Interrupt Read() via the closeFd event fd.
		var value [8]byte
		internal.NativeEndian.PutUint64(value[:], 1)
		_, err = unix.Write(pr.closeFd, value[:])
		if err != nil {
			err = fmt.Errorf("can't write event fd: %v", err)
			return
		}

		// Acquire the lock. This ensures that Read isn't running.
		pr.mu.Lock()
		defer pr.mu.Unlock()

		unix.Close(pr.epollFd)
		unix.Close(pr.closeFd)
		pr.epollFd, pr.closeFd = -1, -1

		// Close rings
		for _, ring := range pr.rings {
			if ring != nil {
				ring.Close()
			}
		}
		pr.rings = nil

		pr.array.Close()
	})
	if err != nil {
		return fmt.Errorf("close PerfReader: %w", err)
	}
	return nil
}

// Read the next record from the BPF ringbuf.
//
// Calling Close interrupts the function.
func (pr *Reader) Read() (Record, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.epollFd == -1 {
		return Record{}, errClosed
	}

	for {
		if len(pr.epollRings) == 0 {
			nEvents, err := unix.EpollWait(pr.epollFd, pr.epollEvents, -1)
			if temp, ok := err.(temporaryError); ok && temp.Temporary() {
				// Retry the syscall if we we're interrupted, see https://github.com/golang/go/issues/20400
				continue
			}

			if err != nil {
				return Record{}, err
			}

			for _, event := range pr.epollEvents[:nEvents] {
				if int(event.Fd) == pr.closeFd {
					return Record{}, errClosed
				}

				ring := pr.rings[0]
				pr.epollRings = append(pr.epollRings, ring)

			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		record, err := readRecordFromRing(pr.epollRings[len(pr.epollRings)-1])
		if err == errEOR {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return record, err
	}
}

type temporaryError interface {
	Temporary() bool
}

// IsClosed returns true if the error occurred because
// a Reader was closed.
func IsClosed(err error) bool {
	return errors.Is(err, errClosed)
}

type unknownEventError struct {
	eventType uint32
}

func (uev *unknownEventError) Error() string {
	return fmt.Sprintf("unknown event type: %d", uev.eventType)
}

// IsUnknownEvent returns true if the error occurred
// because an unknown event was submitted to the perf event ring.
func IsUnknownEvent(err error) bool {
	var uee *unknownEventError
	return errors.As(err, &uee)
}
