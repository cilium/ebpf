package ebpf

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

// perfEventRing is a page of metadata followed by
// a variable number of pages which form a ring buffer.
type perfEventRing struct {
	fd   int
	meta *unix.PerfEventMmapPage
	mmap []byte
	ring []byte
}

func newPerfEventRing(cpu int, opts PerfReaderOptions) (*perfEventRing, error) {

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
		fd:   fd,
		meta: meta,
		mmap: mmap,
		ring: mmap[meta.Data_offset : meta.Data_offset+meta.Data_size],
	}
	runtime.SetFinalizer(ring, (*perfEventRing).Close)

	return ring, nil
}

func createPerfEvent(cpu, watermark int) (int, error) {
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

func createEpollFd(fds ...int) (int, error) {
	epollfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return -1, errors.Wrap(err, "can't create epoll fd")
	}

	for _, fd := range fds {
		event := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(fd),
		}

		err := unix.EpollCtl(epollfd, unix.EPOLL_CTL_ADD, fd, &event)
		if err != nil {
			unix.Close(epollfd)
			return -1, errors.Wrap(err, "can't add fd to epoll")
		}
	}

	return epollfd, nil
}

func (ring *perfEventRing) Close() {
	runtime.SetFinalizer(ring, nil)
	unix.Close(ring.fd)
	unix.Munmap(ring.mmap)
}

func readRecord(rd io.Reader) (*PerfSample, uint64, error) {
	const (
		perfRecordLost   = 2
		perfRecordSample = 9
	)

	var header perfEventHeader
	err := binary.Read(rd, nativeEndian, &header)
	if err == io.EOF {
		return nil, 0, nil
	}

	if err != nil {
		return nil, 0, errors.Wrap(err, "can't read event header")
	}

	switch header.Type {
	case perfRecordLost:
		lost, err := readLostRecords(rd)
		if err != nil {
			return nil, 0, err
		}

		return nil, lost, nil

	case perfRecordSample:
		sample, err := readSample(rd)
		if err != nil {
			return nil, 0, err
		}

		return sample, 0, nil

	default:
		return nil, 0, errors.Errorf("unknown event type %d", header.Type)
	}
}

func readLostRecords(rd io.Reader) (uint64, error) {
	var lostHeader struct {
		ID   uint64
		Lost uint64
	}

	err := binary.Read(rd, nativeEndian, &lostHeader)
	if err != nil {
		return 0, errors.Wrap(err, "can't read lost records header")
	}

	return lostHeader.Lost, nil
}

func readSample(rd io.Reader) (*PerfSample, error) {
	var size uint32
	if err := binary.Read(rd, nativeEndian, &size); err != nil {
		return nil, errors.Wrap(err, "can't read sample size")
	}

	data := make([]byte, int(size))
	_, err := io.ReadFull(rd, data)
	return &PerfSample{data}, errors.Wrap(err, "can't read sample")
}

// PerfSample is read from the kernel by PerfReader.
type PerfSample struct {
	// Data are padded with 0 to have a 64-bit alignment.
	// If you are using variable length samples you need to take
	// this into account.
	Data []byte
}

// PerfReader allows reading bpf_perf_event_output
// from user space.
type PerfReader struct {
	lostSamples uint64
	// Closing a PERF_EVENT_ARRAY removes all event fds
	// stored in it, so we keep a reference alive.
	array *Map

	// Eventfds for closing
	closeFd      int
	flushCloseFd int
	// Ensure we only close once
	closeOnce sync.Once
	// Channel to interrupt polling blocked on writing to consumer
	stopWriter chan struct{}
	// Channel closed when poll() is done
	closed chan struct{}

	// Error receives a write if the reader exits
	// due to an error.
	Error <-chan error

	// Samples is closed when the Reader exits.
	Samples <-chan *PerfSample
}

// PerfReaderOptions control the behaviour of the user
// space reader.
type PerfReaderOptions struct {
	// A map of type PerfEventArray. The reader takes ownership of the
	// map and takes care of closing it.
	Map *Map
	// Controls the size of the per CPU buffer in bytes. LostSamples() will
	// increase if the buffer is too small.
	PerCPUBuffer int
	// The reader will start processing samples once the per CPU buffer
	// exceeds this value. Must be smaller than PerCPUBuffer.
	Watermark int
}

// NewPerfReader creates a new reader with the given options.
//
// The value returned by LostSamples() will increase if the buffer
// isn't large enough to contain all incoming samples.
func NewPerfReader(opts PerfReaderOptions) (out *PerfReader, err error) {
	if opts.PerCPUBuffer < 1 {
		return nil, errors.New("PerCPUBuffer must be larger than 0")
	}

	// We can't create a ring for CPUs that aren't online, so use only the online (of possible) CPUs
	nCPU, err := onlineCPUs()
	if err != nil {
		return nil, errors.Wrap(err, "sampled perf event")
	}

	var (
		fds   []int
		rings = make(map[int]*perfEventRing)
	)

	defer func() {
		if err != nil {
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

		if err := opts.Map.Put(uint32(i), uint32(ring.fd)); err != nil {
			ring.Close()
			return nil, errors.Wrapf(err, "could't put event fd for CPU %d", i)
		}

		fds = append(fds, ring.fd)
		rings[ring.fd] = ring
	}

	closeFd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			unix.Close(closeFd)
		}
	}()
	fds = append(fds, closeFd)

	flushCloseFd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			unix.Close(flushCloseFd)
		}
	}()
	fds = append(fds, flushCloseFd)

	epollFd, err := createEpollFd(fds...)
	if err != nil {
		return nil, err
	}

	samples := make(chan *PerfSample, nCPU)
	errs := make(chan error, 1)

	out = &PerfReader{
		array:        opts.Map,
		closeFd:      closeFd,
		flushCloseFd: flushCloseFd,
		stopWriter:   make(chan struct{}),
		closed:       make(chan struct{}),
		Error:        errs,
		Samples:      samples,
	}
	runtime.SetFinalizer(out, (*PerfReader).Close)

	go out.poll(epollFd, rings, samples, errs)

	return out, nil
}

// LostSamples returns the number of samples dropped
// by the perf subsystem.
func (pr *PerfReader) LostSamples() uint64 {
	return atomic.LoadUint64(&pr.lostSamples)
}

// Close stops the reader, discarding any samples not yet written to 'Samples'.
//
// Calls to perf_event_output from eBPF programs will return
// ENOENT after calling this method.
func (pr *PerfReader) Close() (err error) {
	return pr.close(false)
}

// FlushAndClose stops the reader, flushing any samples to 'Samples'.
// Will block if no consumer reads from 'Samples'.
//
// Calls to perf_event_output from eBPF programs will return
// ENOENT after calling this method.
func (pr *PerfReader) FlushAndClose() error {
	return pr.close(true)
}

func (pr *PerfReader) close(flush bool) error {
	pr.closeOnce.Do(func() {
		runtime.SetFinalizer(pr, nil)

		// Interrupt polling so we don't deadlock if the consumer is dead
		if !flush {
			close(pr.stopWriter)
		}

		// Signal poll() via the event fd. Ignore the
		// write error since poll() may have exited
		// and closed the fd already
		var value [8]byte
		nativeEndian.PutUint64(value[:], 1)
		if flush {
			_, _ = unix.Write(pr.flushCloseFd, value[:])
		} else {
			_, _ = unix.Write(pr.closeFd, value[:])
		}
	})

	// Wait until poll is done
	<-pr.closed

	return nil
}

func (pr *PerfReader) poll(epollFd int, rings map[int]*perfEventRing, samples chan<- *PerfSample, errs chan<- error) {
	// last as it means we're done
	defer close(pr.closed)
	defer close(samples)
	defer pr.array.Close()
	defer unix.Close(epollFd)
	defer unix.Close(pr.closeFd)
	defer unix.Close(pr.flushCloseFd)
	defer func() {
		for _, ring := range rings {
			ring.Close()
		}
	}()

	epollEvents := make([]unix.EpollEvent, len(rings)+1)

	for {
		nEvents, err := unix.EpollWait(epollFd, epollEvents, -1)
		if err != nil {
			// Handle EINTR
			if temp, ok := err.(temporaryError); ok && temp.Temporary() {
				continue
			}

			errs <- err
			return
		}

		for _, event := range epollEvents[:nEvents] {
			fd := int(event.Fd)
			if fd == pr.closeFd {
				// We were woken by Close via the close fd
				return
			}

			if fd == pr.flushCloseFd {
				for _, ring := range rings {
					err := pr.flushRing(ring, samples)
					if err != nil {
						errs <- err
						return
					}
				}

				return
			}

			err := pr.flushRing(rings[fd], samples)
			if err != nil {
				errs <- err
				return
			}
		}
	}
}

func (pr *PerfReader) flushRing(ring *perfEventRing, samples chan<- *PerfSample) error {
	rd := newRingReader(ring.meta, ring.ring)
	defer rd.Close()

	var totalLost uint64

	for {
		sample, lost, err := readRecord(rd)
		if err != nil {
			return err
		}

		if lost > 0 {
			totalLost += lost
			continue
		}

		if sample == nil {
			break
		}

		select {
		case samples <- sample:
		case <-pr.stopWriter:
			break
		}
	}

	if totalLost > 0 {
		atomic.AddUint64(&pr.lostSamples, totalLost)
	}
	return nil
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

func (rb *ringReader) Close() error {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&rb.meta.Data_tail, rb.tail)
	return nil
}

func (rb *ringReader) Read(p []byte) (int, error) {
	start := int(rb.tail & rb.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rb.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rb.head - rb.tail); n > remainder {
		n = remainder
	}

	copy(p, rb.ring[start:start+n])
	rb.tail += uint64(n)

	if rb.tail == rb.head {
		return n, io.EOF
	}

	return n, nil
}

type temporaryError interface {
	Temporary() bool
}
