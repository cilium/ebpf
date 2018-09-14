package ebpf

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	perfTypeSoftware     = 1
	perfCountSWBPFOutput = 10
	perfSampleRaw        = 1 << 10
)

type perfEventMeta struct {
	_          [128]uint64 /* Pad to 1 k, ignore fields */
	dataHead   uint64      /* head in the data section */
	dataTail   uint64      /* user-space written tail */
	dataOffset uint64      /* where the buffer starts */
	dataSize   uint64      /* data buffer size */
}

type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

// perfEventRing is a page of metadata followed by
// a variable number of pages which form a ring buffer.
type perfEventRing struct {
	fd   int
	meta *perfEventMeta
	mmap []byte
	ring []byte
}

func newPerfEventRing(cpu int, opts PerfReaderOptions) (*perfEventRing, error) {
	const flagWakeupWatermark = 1 << 14

	if opts.Watermark >= opts.PerCPUBuffer {
		return nil, errors.Errorf("Watermark must be smaller than PerCPUBuffer")
	}

	// Round to nearest page boundary and allocate
	// an extra page for meta data
	pageSize := os.Getpagesize()
	nPages := (opts.PerCPUBuffer + pageSize - 1) / pageSize
	size := (1 + nPages) * pageSize

	attr := perfEventAttr{
		perfType:                perfTypeSoftware,
		config:                  perfCountSWBPFOutput,
		flags:                   flagWakeupWatermark,
		sampleType:              perfSampleRaw,
		wakeupEventsOrWatermark: uint32(opts.Watermark),
	}

	fd, err := perfEventOpen(&attr, -1, cpu, -1, 0)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	mmap, err := syscall.Mmap(fd, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// This relies on the fact that we allocate an extra metadata page,
	// and that the struct is smaller than an OS page.
	// This use of unsafe.Pointer isn't explicitly sanctioned by the
	// documentation, since a byte is smaller than sampledPerfEvent.
	meta := (*perfEventMeta)(unsafe.Pointer(&mmap[0]))

	return &perfEventRing{
		fd:   fd,
		meta: meta,
		mmap: mmap,
		ring: mmap[meta.dataOffset : meta.dataOffset+meta.dataSize],
	}, nil
}

func (ring *perfEventRing) Close() {
	syscall.Close(ring.fd)
	syscall.Munmap(ring.mmap)
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

	closeOnce sync.Once
	closeFile *os.File
	close     chan struct{}

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

	nCPU, err := possibleCPUs()
	if err != nil {
		opts.Map.Close()
		return nil, errors.Wrap(err, "sampled perf event")
	}

	closeFd, err := newEventFd()
	if err != nil {
		opts.Map.Close()
		return nil, err
	}

	samples := make(chan *PerfSample, nCPU)
	errs := make(chan error, 1)

	out = &PerfReader{
		array:     opts.Map,
		closeFile: os.NewFile(uintptr(closeFd), "event fd"),
		close:     make(chan struct{}),
		Error:     errs,
		Samples:   samples,
	}
	runtime.SetFinalizer(out, (*PerfReader).Close)

	var (
		fds   = []int{closeFd}
		rings = make(map[int]*perfEventRing)
	)

	defer func() {
		if err != nil {
			for _, mmap := range rings {
				mmap.Close()
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

	epollfd, err := newEpollFd(fds...)
	if err != nil {
		return nil, err
	}

	go out.poll(epollfd, rings, samples, errs)
	return out, nil
}

// LostSamples returns the number of samples dropped
// by the perf subsystem.
func (pr *PerfReader) LostSamples() uint64 {
	return atomic.LoadUint64(&pr.lostSamples)
}

// Close stops the reader.
//
// Calls to perf_event_output from eBPF programs will return
// ENOENT after calling this method.
func (pr *PerfReader) Close() (err error) {
	pr.closeOnce.Do(func() {
		runtime.SetFinalizer(pr, nil)

		// Indicate that we want to shut down
		close(pr.close)
		pr.array.Close()

		// Signal poll() via the event fd
		var value [8]byte
		nativeEndian.PutUint64(value[:], 1)
		_, err = pr.closeFile.Write(value[:])
	})

	return errors.Wrap(err, "can't write to event fd")
}

func (pr *PerfReader) poll(epollFd int, rings map[int]*perfEventRing, samples chan<- *PerfSample, errs chan<- error) {
	defer close(samples)
	defer syscall.Close(epollFd)
	defer func() {
		for _, ring := range rings {
			ring.Close()
		}
	}()

	epollEvents := make([]syscall.EpollEvent, len(rings))

	for {
		nEvents, err := syscall.EpollWait(epollFd, epollEvents, -1)
		if err != nil {
			// Handle EINTR
			if temp, ok := err.(temporaryError); ok && temp.Temporary() {
				continue
			}

			errs <- err
			return
		}

		select {
		case <-pr.close:
			// We were woken by Close via the event fd
			return
		default:
		}

		for _, event := range epollEvents[:nEvents] {
			ring := rings[int(event.Fd)]
			err := pr.flushRing(ring, samples)
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
		case <-pr.close:
			break
		}
	}

	if totalLost > 0 {
		atomic.AddUint64(&pr.lostSamples, totalLost)
	}
	return nil
}

type ringReader struct {
	meta       *perfEventMeta
	head, tail uint64
	mask       uint64
	ring       []byte
}

func newRingReader(meta *perfEventMeta, ring []byte) *ringReader {
	return &ringReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.dataHead),
		tail: atomic.LoadUint64(&meta.dataTail),
		// cap is always a power of two
		mask: uint64(cap(ring) - 1),
		ring: ring,
	}
}

func (rb *ringReader) Close() error {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&rb.meta.dataTail, rb.tail)
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
