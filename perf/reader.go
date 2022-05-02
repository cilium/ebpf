package perf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrClosed = os.ErrClosed
	errEOR    = errors.New("end of ring")
)

// perfEventHeader must match 'struct perf_event_header` in <linux/perf_event.h>.
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

func (h *perfEventHeader) UnmarshalBinary(buf []byte) error {
	h.Type = internal.NativeEndian.Uint32(buf[0:4])
	// these fields are currently unused
	//h.Misc = internal.NativeEndian.Uint16(buf[4:6])
	//h.Size = internal.NativeEndian.Uint16(buf[6:8])
	return nil
}

var perfEventHeaderSize = binary.Size(perfEventHeader{})
var perfEventHeaderPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, perfEventHeaderSize)
		return &buf
	},
}

type bufferSize uint32

var bufferSizeSize = binary.Size(bufferSize(0))
var bufferSizePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, bufferSizeSize)
		return &buf
	},
}

func (b *bufferSize) UnmarshalBinary(buf []byte) error {
	*b = bufferSize(internal.NativeEndian.Uint32(buf))
	return nil
}

func cpuForEvent(event *unix.EpollEvent) int {
	return int(event.Pad)
}

// Record contains either a sample or a counter of the
// number of lost samples.
type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
	// garbage from the ring depending on the input sample's length.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64
}

// NB: Has to be preceded by a call to ring.loadHead.
func (pr *Reader) readRecordFromRing(ring *perfEventRing) (Record, error) {
	defer ring.writeTail()
	return pr.readRecord(ring, ring.cpu)
}

func (pr *Reader) readRecord(rd io.Reader, cpu int) (Record, error) {
	var header perfEventHeader
	if err := readHeader(rd, &header); err != nil {
		return Record{}, err
	}

	switch header.Type {
	case unix.PERF_RECORD_LOST:
		lost, err := readLostRecords(rd)
		return Record{CPU: cpu, LostSamples: lost}, err

	case unix.PERF_RECORD_SAMPLE:
		// This must match 'struct perf_event_sample in kernel sources.
		var size bufferSize
		if err := readSampleSize(rd, &size); err != nil {
			return Record{}, err
		}
		if len(pr.readBufs[cpu]) < int(size) {
			pr.readBufs[cpu] = make([]byte, size)
		}
		buf := pr.readBufs[cpu][:size]
		if _, err := io.ReadFull(rd, buf); err != nil {
			return Record{}, fmt.Errorf("can't read sample: %v", err)
		}
		return Record{CPU: cpu, RawSample: buf}, nil

	default:
		return Record{}, &unknownEventError{header.Type}
	}
}

func readHeader(rd io.Reader, header *perfEventHeader) error {
	headerSlicePtr := perfEventHeaderPool.Get().(*[]byte)
	defer perfEventHeaderPool.Put(headerSlicePtr)

	headerSlice := *headerSlicePtr
	if _, err := io.ReadFull(rd, headerSlice); err != nil {
		if err == io.EOF {
			return errEOR
		}
		return fmt.Errorf("can't read event header: %v", err)
	}
	if err := header.UnmarshalBinary(headerSlice); err != nil {
		return fmt.Errorf("can't unmarshal event header: %v", err)
	}
	return nil
}

func readSampleSize(rd io.Reader, size *bufferSize) error {
	sizeSlicePtr := bufferSizePool.Get().(*[]byte)
	defer bufferSizePool.Put(sizeSlicePtr)
	sizeSlice := *sizeSlicePtr
	if _, err := io.ReadFull(rd, sizeSlice); err != nil {
		return fmt.Errorf("can't read sample size: %v", err)
	}
	if err := size.UnmarshalBinary(sizeSlice); err != nil {
		return fmt.Errorf("can't unmarshal event header: %v", err)
	}
	return nil
}

func readLostRecords(rd io.Reader) (uint64, error) {
	// lostHeader must match 'struct perf_event_lost in kernel sources.
	var lostHeader struct {
		ID   uint64
		Lost uint64
	}

	err := binary.Read(rd, internal.NativeEndian, &lostHeader)
	if err != nil {
		return 0, fmt.Errorf("can't read lost records header: %v", err)
	}

	return lostHeader.Lost, nil
}

// Reader allows reading bpf_perf_event_output
// from user space.
type Reader struct {
	poller *epoll.Poller

	// mu protects read/write access to the Reader structure with the
	// exception of 'pauseFds', which is protected by 'pauseMu'.
	// If locking both 'mu' and 'pauseMu', 'mu' must be locked first.
	mu sync.Mutex

	// Closing a PERF_EVENT_ARRAY removes all event fds
	// stored in it, so we keep a reference alive.
	array       *ebpf.Map
	rings       []*perfEventRing
	epollEvents []unix.EpollEvent
	epollRings  []*perfEventRing
	readBufs    [][]byte

	// pauseFds are a copy of the fds in 'rings', protected by 'pauseMu'.
	// These allow Pause/Resume to be executed independently of any ongoing
	// Read calls, which would otherwise need to be interrupted.
	pauseMu  sync.Mutex
	pauseFds []int
}

// ReaderOptions control the behaviour of the user
// space reader.
type ReaderOptions struct {
	// The number of written bytes required in any per CPU buffer before
	// Read will process data. Must be smaller than PerCPUBuffer.
	// The default is to start processing as soon as data is available.
	Watermark int
}

// NewReader creates a new reader with default options.
//
// array must be a PerfEventArray. perCPUBuffer gives the size of the
// per CPU buffer in bytes. It is rounded up to the nearest multiple
// of the current page size.
func NewReader(array *ebpf.Map, perCPUBuffer int) (*Reader, error) {
	return NewReaderWithOptions(array, perCPUBuffer, ReaderOptions{})
}

// NewReaderWithOptions creates a new reader with the given options.
func NewReaderWithOptions(array *ebpf.Map, perCPUBuffer int, opts ReaderOptions) (pr *Reader, err error) {
	if perCPUBuffer < 1 {
		return nil, errors.New("perCPUBuffer must be larger than 0")
	}

	var (
		fds      []int
		nCPU     = int(array.MaxEntries())
		rings    = make([]*perfEventRing, 0, nCPU)
		pauseFds = make([]int, 0, nCPU)
	)

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			poller.Close()
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

	// bpf_perf_event_output checks which CPU an event is enabled on,
	// but doesn't allow using a wildcard like -1 to specify "all CPUs".
	// Hence we have to create a ring for each CPU.
	for i := 0; i < nCPU; i++ {
		ring, err := newPerfEventRing(i, perCPUBuffer, opts.Watermark)
		if errors.Is(err, unix.ENODEV) {
			// The requested CPU is currently offline, skip it.
			rings = append(rings, nil)
			pauseFds = append(pauseFds, -1)
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create perf ring for CPU %d: %v", i, err)
		}
		rings = append(rings, ring)
		pauseFds = append(pauseFds, ring.fd)

		if err := poller.Add(ring.fd, i); err != nil {
			return nil, err
		}
	}

	array, err = array.Clone()
	if err != nil {
		return nil, err
	}

	pr = &Reader{
		array:       array,
		rings:       rings,
		poller:      poller,
		epollEvents: make([]unix.EpollEvent, len(rings)),
		epollRings:  make([]*perfEventRing, 0, len(rings)),
		pauseFds:    pauseFds,
		readBufs:    make([][]byte, nCPU),
	}
	if err = pr.Resume(); err != nil {
		return nil, err
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
	if err := pr.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return fmt.Errorf("close poller: %w", err)
	}

	// Trying to poll will now fail, so Read() can't block anymore. Acquire the
	// lock so that we can clean up.
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for _, ring := range pr.rings {
		if ring != nil {
			ring.Close()
		}
	}
	pr.rings = nil
	pr.pauseFds = nil
	pr.array.Close()

	return nil
}

var bytesReaderPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Reader)
	},
}

// Unmarshal the next record from the perf ring buffer.
//
// The function blocks until there are at least Watermark bytes in one
// of the per CPU buffers. Records from buffers below the Watermark
// are not returned.
//
// If the object implements the `encoding.BinaryUnmarshaler` interface,
// `UnmarshalBinary` will be called on it.
//
// Calling Close interrupts the function.
func (pr *Reader) Unmarshal(valueOut interface{}) (cpu int, lost uint64, err error) {
	record, err := pr.read()
	if err != nil {
		return 0, 0, err
	}
	if record.LostSamples > 0 || len(record.RawSample) == 0 {
		return record.CPU, record.LostSamples, nil
	}

	err = unmarshalBytes(valueOut, record.RawSample)
	return record.CPU, 0, err
}

func unmarshalBytes(data interface{}, buf []byte) error {
	switch value := data.(type) {
	case encoding.BinaryUnmarshaler:
		return value.UnmarshalBinary(buf)
	case *[]byte:
		if len(*value) < len(buf) {
			return fmt.Errorf("provided byte slice is too small. expected %d", len(buf))
		}
		copy(*value, buf)
		return nil
	default:
		rd := bytesReaderPool.Get().(*bytes.Reader)
		rd.Reset(buf)
		defer bytesReaderPool.Put(rd)
		return binary.Read(rd, internal.NativeEndian, value)
	}
}

// Read the next record from the perf ring buffer.
//
// The function blocks until there are at least Watermark bytes in one
// of the per CPU buffers. Records from buffers below the Watermark
// are not returned.
//
// Records can contain between 0 and 7 bytes of trailing garbage from the ring
// depending on the input sample's length.
//
// Calling Close interrupts the function.
func (pr *Reader) Read() (Record, error) {
	record, err := pr.read()
	if err != nil {
		return Record{}, err
	}
	// maintain previous behavior and copy the per-CPU buffer contents to new slice
	if len(record.RawSample) > 0 {
		tmp := make([]byte, len(record.RawSample))
		copy(tmp, record.RawSample)
		record.RawSample = tmp
	}
	return record, nil
}

func (pr *Reader) read() (Record, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.rings == nil {
		return Record{}, fmt.Errorf("perf ringbuffer: %w", ErrClosed)
	}

	for {
		if len(pr.epollRings) == 0 {
			nEvents, err := pr.poller.Wait(pr.epollEvents)
			if err != nil {
				return Record{}, err
			}

			for _, event := range pr.epollEvents[:nEvents] {
				ring := pr.rings[cpuForEvent(&event)]
				pr.epollRings = append(pr.epollRings, ring)

				// Read the current head pointer now, not every time
				// we read a record. This prevents a single fast producer
				// from keeping the reader busy.
				ring.loadHead()
			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		record, err := pr.readRecordFromRing(pr.epollRings[len(pr.epollRings)-1])
		if err == errEOR {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return record, err
	}
}

// Pause stops all notifications from this Reader.
//
// While the Reader is paused, any attempts to write to the event buffer from
// BPF programs will return -ENOENT.
//
// Subsequent calls to Read will block until a call to Resume.
func (pr *Reader) Pause() error {
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.pauseFds == nil {
		return fmt.Errorf("%w", ErrClosed)
	}

	for i := range pr.pauseFds {
		if err := pr.array.Delete(uint32(i)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("could't delete event fd for CPU %d: %w", i, err)
		}
	}

	return nil
}

// Resume allows this perf reader to emit notifications.
//
// Subsequent calls to Read will block until the next event notification.
func (pr *Reader) Resume() error {
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.pauseFds == nil {
		return fmt.Errorf("%w", ErrClosed)
	}

	for i, fd := range pr.pauseFds {
		if fd == -1 {
			continue
		}

		if err := pr.array.Put(uint32(i), uint32(fd)); err != nil {
			return fmt.Errorf("couldn't put event fd %d for CPU %d: %w", fd, i, err)
		}
	}

	return nil
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
