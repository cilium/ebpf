package perf

import (
	"encoding/binary"
	"io"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var errClosed = errors.New("perf reader was closed")

// perfEventHeader must match 'struct perf_event_header` in <linux/perf_event.h>.
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

// perfEventRing is a page of metadata followed by
// a variable number of pages which form a ring buffer.
type perfEventRing struct {
	fd     int
	cpu    int
	mmap   []byte
	reader *ringReader
}

func newPerfEventRing(cpu int, opts ReaderOptions) (*perfEventRing, error) {
	if opts.Watermark >= opts.PerCPUBuffer {
		return nil, errors.Errorf("Watermark must be smaller than PerCPUBuffer")
	}

	// Round to nearest page boundary and allocate
	// an extra page for meta data
	pageSize := os.Getpagesize()
	nPages := (opts.PerCPUBuffer + pageSize - 1) / pageSize
	size := (1 + nPages) * pageSize

	fd, err := createPerfEvent(cpu, opts.Watermark)
	if err != nil {
		return nil, errors.Wrap(err, "can't create perf event")
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	mmap, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	// This relies on the fact that we allocate an extra metadata page,
	// and that the struct is smaller than an OS page.
	// This use of unsafe.Pointer isn't explicitly sanctioned by the
	// documentation, since a byte is smaller than sampledPerfEvent.
	meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(&mmap[0]))

	ring := &perfEventRing{
		fd:     fd,
		cpu:    cpu,
		mmap:   mmap,
		reader: newRingReader(meta, mmap[meta.Data_offset:meta.Data_offset+meta.Data_size]),
	}
	runtime.SetFinalizer(ring, (*perfEventRing).Close)

	return ring, nil
}

func createPerfEvent(cpu, watermark int) (int, error) {
	if watermark == 0 {
		watermark = 1
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))

	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err == nil {
		return fd, nil
	}

	switch err {
	case unix.E2BIG:
		return -1, errors.WithMessage(unix.E2BIG, "perf_event_attr size is incorrect,check size field for what the correct size should be")
	case unix.EACCES:
		return -1, errors.WithMessage(unix.EACCES, "insufficient capabilities to create this event")
	case unix.EBADFD:
		return -1, errors.WithMessage(unix.EBADFD, "group_fd is invalid")
	case unix.EBUSY:
		return -1, errors.WithMessage(unix.EBUSY, "another event already has exclusive access to the PMU")
	case unix.EFAULT:
		return -1, errors.WithMessage(unix.EFAULT, "attr points to an invalid address")
	case unix.EINVAL:
		return -1, errors.WithMessage(unix.EINVAL, "the specified event is invalid, most likely because a configuration parameter is invalid (i.e. too high, too low, etc)")
	case unix.EMFILE:
		return -1, errors.WithMessage(unix.EMFILE, "this process has reached its limits for number of open events that it may have")
	case unix.ENODEV:
		return -1, errors.WithMessage(unix.ENODEV, "this processor architecture does not support this event type")
	case unix.ENOENT:
		return -1, errors.WithMessage(unix.ENOENT, "the type setting is not valid")
	case unix.ENOSPC:
		return -1, errors.WithMessage(unix.ENOSPC, "the hardware limit for breakpoints)capacity has been reached")
	case unix.ENOSYS:
		return -1, errors.WithMessage(unix.ENOSYS, "sample type not supported by the hardware")
	case unix.EOPNOTSUPP:
		return -1, errors.WithMessage(unix.EOPNOTSUPP, "this event is not supported by the hardware or requires a feature not supported by the hardware")
	case unix.EOVERFLOW:
		return -1, errors.WithMessage(unix.EOVERFLOW, "sample_max_stack is larger than the kernel support; check \"/proc/sys/kernel/perf_event_max_stack\" for maximum supported size")
	case unix.EPERM:
		return -1, errors.WithMessage(unix.EPERM, "insufficient capability to request exclusive access")
	case unix.ESRCH:
		return -1, errors.WithMessage(unix.ESRCH, "pid does not exist")
	default:
		return -1, err
	}
}

func addToEpoll(epollfd, fd int, cpu int) error {
	if int64(cpu) > math.MaxInt32 {
		return errors.Errorf("unsupported CPU number: %d", cpu)
	}

	// The representation of EpollEvent isn't entirely accurate.
	// Pad is fully useable, not just padding. Hence we stuff the
	// CPU in there, which allows us to use a slice to access
	// the correct perf ring.
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
		Pad:    int32(cpu),
	}

	err := unix.EpollCtl(epollfd, unix.EPOLL_CTL_ADD, fd, &event)
	return errors.Wrap(err, "can't add fd to epoll")
}

func cpuForEvent(event *unix.EpollEvent) int {
	return int(event.Pad)
}

func (ring *perfEventRing) Close() {
	runtime.SetFinalizer(ring, nil)
	unix.Close(ring.fd)
	unix.Munmap(ring.mmap)

	ring.fd = -1
	ring.mmap = nil
}

func (ring *perfEventRing) LoadHead() {
	ring.reader.loadHead()
}

// NB: Has to be preceded by a call to LoadHead.
func (ring *perfEventRing) ReadRecord() (*Record, error) {
	if ring.fd == -1 {
		return nil, errClosed
	}

	defer ring.reader.writeTail()
	return readRecord(ring.reader, ring.cpu)
}

// Record contains either a sample or a counter of the
// number of lost samples.
type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	// They are padded with 0 to have a 64-bit alignment.
	// If you are using variable length samples you need to take
	// this into account.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64
}

func readRecord(rd io.Reader, cpu int) (*Record, error) {
	const (
		perfRecordLost   = 2
		perfRecordSample = 9
	)

	var header perfEventHeader
	err := binary.Read(rd, internal.NativeEndian, &header)
	if err == io.EOF {
		return nil, nil
	}

	if err != nil {
		return nil, errors.Wrap(err, "can't read event header")
	}

	switch header.Type {
	case perfRecordLost:
		lost, err := readLostRecords(rd)
		return &Record{CPU: cpu, LostSamples: lost}, err

	case perfRecordSample:
		sample, err := readRawSample(rd)
		return &Record{CPU: cpu, RawSample: sample}, err

	default:
		return nil, errors.Errorf("unknown event type %d", header.Type)
	}
}

func readLostRecords(rd io.Reader) (uint64, error) {
	// lostHeader must match 'struct perf_event_lost in kernel sources.
	var lostHeader struct {
		ID   uint64
		Lost uint64
	}

	err := binary.Read(rd, internal.NativeEndian, &lostHeader)
	if err != nil {
		return 0, errors.Wrap(err, "can't read lost records header")
	}

	return lostHeader.Lost, nil
}

func readRawSample(rd io.Reader) ([]byte, error) {
	// This must match 'struct perf_event_sample in kernel sources.
	var size uint32
	if err := binary.Read(rd, internal.NativeEndian, &size); err != nil {
		return nil, errors.Wrap(err, "can't read sample size")
	}

	data := make([]byte, int(size))
	_, err := io.ReadFull(rd, data)
	return data, errors.Wrap(err, "can't read sample")
}

// Reader allows reading bpf_perf_event_output
// from user space.
type Reader struct {
	mu sync.Mutex

	// Closing a PERF_EVENT_ARRAY removes all event fds
	// stored in it, so we keep a reference alive.
	array *ebpf.Map
	rings []*perfEventRing

	epollFd     int
	epollEvents []unix.EpollEvent
	epollRings  []*perfEventRing
	// Eventfds for closing
	closeFd int
	// Ensure we only close once
	closeOnce sync.Once
}

// ReaderOptions control the behaviour of the user
// space reader.
type ReaderOptions struct {
	// A map of type PerfEventArray.
	Map *ebpf.Map
	// Controls the size of the per CPU buffer in bytes. It is rounded up
	// to the nearest multiple of the current page size.
	PerCPUBuffer int
	// The number of written bytes required in any per CPU buffer before
	// Read will process data. Must be smaller than PerCPUBuffer.
	// The default is to start processing as soon as data is available.
	Watermark int
}

// NewReader creates a new reader with the given options.
func NewReader(opts ReaderOptions) (pr *Reader, err error) {
	if opts.PerCPUBuffer < 1 {
		return nil, errors.New("PerCPUBuffer must be larger than 0")
	}

	// We can't create a ring for CPUs that aren't online, so use only the online (of possible) CPUs
	nCPU, err := internal.OnlineCPUs()
	if err != nil {
		return nil, err
	}

	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, errors.Wrap(err, "can't create epoll fd")
	}

	var (
		fds   = []int{epollFd}
		rings = make([]*perfEventRing, 0, nCPU)
	)

	defer func() {
		if err != nil {
			for _, fd := range fds {
				unix.Close(fd)
			}
			for _, ring := range rings {
				ring.Close()
			}
		}
	}()

	// bpf_perf_event_output checks which CPU an event is enabled on,
	// but doesn't allow using a wildcard like -1 to specify "all CPUs".
	// Hence we have to create a ring for each CPU.
	for i := 0; i < nCPU; i++ {
		ring, err := newPerfEventRing(i, opts)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create perf ring for CPU %d", i)
		}
		rings = append(rings, ring)

		if err := opts.Map.Put(uint32(i), uint32(ring.fd)); err != nil {
			return nil, errors.Wrapf(err, "could't put event fd for CPU %d", i)
		}

		if err := addToEpoll(epollFd, ring.fd, len(rings)-1); err != nil {
			return nil, err
		}
	}

	closeFd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	fds = append(fds, closeFd)

	if err := addToEpoll(epollFd, closeFd, -1); err != nil {
		return nil, err
	}

	array, err := opts.Map.Clone()
	if err != nil {
		return nil, err
	}

	pr = &Reader{
		array:   array,
		rings:   rings,
		epollFd: epollFd,
		// Allocate extra event for closeFd
		epollEvents: make([]unix.EpollEvent, len(rings)+1),
		epollRings:  make([]*perfEventRing, 0, len(rings)),
		closeFd:     closeFd,
	}
	runtime.SetFinalizer(pr, (*Reader).Close)
	return pr, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
//
// Calls to perf_event_output from eBPF programs will return
// ENOENT after calling this method.
func (pr *Reader) Close() error {
	var err error
	pr.closeOnce.Do(func() {
		runtime.SetFinalizer(pr, nil)

		// Interrupt Read() via the event fd.
		var value [8]byte
		internal.NativeEndian.PutUint64(value[:], 1)
		_, err = unix.Write(pr.closeFd, value[:])
		if err != nil {
			err = errors.Wrap(err, "can't write event fd")
			return
		}

		// Acquire the lock. This ensures that Read
		// isn't running.
		pr.mu.Lock()
		defer pr.mu.Unlock()

		unix.Close(pr.epollFd)
		unix.Close(pr.closeFd)
		pr.epollFd, pr.closeFd = -1, -1

		// Close rings
		for _, ring := range pr.rings {
			ring.Close()
		}
		pr.rings = nil

		pr.array.Close()
	})

	return errors.Wrap(err, "close PerfReader")
}

// Read the next record from the perf ring buffer.
//
// The function blocks until there are at least Watermark bytes in one
// of the per CPU buffers.
//
// Records from buffers below the Watermark are not returned.
//
// Calling Close interrupts the function.
func (pr *Reader) Read() (*Record, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.epollFd == -1 {
		return nil, errClosed
	}

	for {
		if len(pr.epollRings) == 0 {
			nEvents, err := unix.EpollWait(pr.epollFd, pr.epollEvents, -1)
			if temp, ok := err.(temporaryError); ok && temp.Temporary() {
				// Retry the syscall if we we're interrupted, see https://github.com/golang/go/issues/20400
				continue
			}

			if err != nil {
				return nil, err
			}

			for _, event := range pr.epollEvents[:nEvents] {
				if int(event.Fd) == pr.closeFd {
					return nil, errClosed
				}

				ring := pr.rings[cpuForEvent(&event)]
				pr.epollRings = append(pr.epollRings, ring)

				// Read the current head pointer now, not every time
				// we read a record. This prevents a single fast producer
				// from keeping the reader busy.
				ring.LoadHead()
			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		record, err := pr.epollRings[len(pr.epollRings)-1].ReadRecord()
		if err != nil {
			return nil, err
		}

		if record == nil {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return record, nil
	}
}

type ringReader struct {
	meta       *unix.PerfEventMmapPage
	head, tail uint64
	mask       uint64
	ring       []byte
}

func newRingReader(meta *unix.PerfEventMmapPage, ring []byte) *ringReader {
	return &ringReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.Data_head),
		tail: atomic.LoadUint64(&meta.Data_tail),
		// cap is always a power of two
		mask: uint64(cap(ring) - 1),
		ring: ring,
	}
}

func (rr *ringReader) loadHead() {
	rr.head = atomic.LoadUint64(&rr.meta.Data_head)
}

func (rr *ringReader) writeTail() {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&rr.meta.Data_tail, rr.tail)
}

func (rr *ringReader) Read(p []byte) (int, error) {
	start := int(rr.tail & rr.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rr.head - rr.tail); n > remainder {
		n = remainder
	}

	copy(p, rr.ring[start:start+n])
	rr.tail += uint64(n)

	if rr.tail == rr.head {
		return n, io.EOF
	}

	return n, nil
}

type temporaryError interface {
	Temporary() bool
}

// IsClosed returns true if the error occurred because
// a Reader was closed.
func IsClosed(err error) bool {
	return errors.Cause(err) == errClosed
}
