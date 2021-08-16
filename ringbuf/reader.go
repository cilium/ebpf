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
	errClosed  = errors.New("ringbuf reader was closed")
	errDiscard = errors.New("sample discarded")
	errBusy    = errors.New("sample not committed yet")
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

func readRecordFromRing(ring *ringbufEventRing) (Record, error) {
	return readRecord(ring)
}

func readRecord(rd io.Reader) (Record, error) {
	var header ringbufHeader
	err := binary.Read(rd, internal.NativeEndian, &header)
	if err == io.EOF {
		return Record{}, err
	}

	if err != nil {
		return Record{}, fmt.Errorf("can't read event header: %v", err)
	}

	if header.Len&unix.BPF_RINGBUF_BUSY_BIT != 0 {
		return Record{}, errBusy
	}

	dataLen := header.Len << 2
	dataLen >>= 2

	/* read up to 8 byte alignment */
	data := make([]byte, (dataLen+7)/8*8)
	if _, err := io.ReadFull(rd, data); err != nil {
		return Record{}, fmt.Errorf("can't read sample: %v", err)
	}

	if header.Len&unix.BPF_RINGBUF_DISCARD_BIT == 0 {
		return Record{RawSample: data[:dataLen]}, nil
	}

	return Record{}, errDiscard

}

// Reader allows reading bpf_ringbuf_output
// from user space.
type Reader struct {
	// mu protects read/write access to the Reader structure
	mu sync.Mutex

	array *ebpf.Map
	mapFd int
	ring  *ringbufEventRing

	epollFd     int
	epollEvents []unix.EpollEvent
	pollTimeout int

	closeFd int
	// Ensure we only close once
	closeOnce sync.Once
}

// ReaderOptions control the behaviour of the user
// space reader.
type ReaderOptions struct {
	pollTimeout int
}

// NewReader creates a new BPF ringbuf reader.
func NewReader(array *ebpf.Map) (*Reader, error) {
	return NewReaderWithOptions(array, ReaderOptions{pollTimeout: -1})
}

func NewReaderWithOptions(array *ebpf.Map, opts ReaderOptions) (*Reader, error) {
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("can't create epoll fd: %v", err)
	}

	var (
		fds        = []int{epollFd}
		maxEntries = int(array.MaxEntries())
		ring       *ringbufEventRing
	)

	if maxEntries != 0 && (maxEntries&(maxEntries-1)) != 0 {
		return nil, fmt.Errorf("Ringbuffer map size %d is not a power of two", maxEntries)
	}
	defer func() {
		if err != nil {
			// close epollFd and closeFd
			for _, fd := range fds {
				unix.Close(fd)
			}
			if ring != nil {
				ring.Close()
			}
		}
	}()

	ring, err = newRingBufEventRing(array.FD(), maxEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf ring: %v", err)
	}

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
		ring:    ring,
		array:   array,
		mapFd:   array.FD(),
		epollFd: epollFd,
		// Allocate extra event for closeFd
		epollEvents: make([]unix.EpollEvent, 2),
		pollTimeout: opts.pollTimeout,
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

		if pr.ring != nil {
			pr.ring.Close()
		}
		pr.ring = nil

		pr.array.Close()
	})
	if err != nil {
		return fmt.Errorf("close RingbufReader: %w", err)
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
		nEvents, err := unix.EpollWait(pr.epollFd, pr.epollEvents, pr.pollTimeout)
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
		}

		pr.ring.loadConsumer()

		record, err := readRecordFromRing(pr.ring)
		if err == errBusy {
			continue
		}

		pr.ring.storeConsumer()

		if err == errDiscard {
			continue
		}
		return record, err
	}
}

type temporaryError interface {
	Temporary() bool
}
