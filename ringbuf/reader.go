package ringbuf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrClosed  = os.ErrClosed
	errDiscard = errors.New("sample discarded")
	errBusy    = errors.New("sample not committed yet")
)

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len   uint32
	PgOff uint32
}

func (rh *ringbufHeader) isBusy() bool {
	return rh.Len&unix.BPF_RINGBUF_BUSY_BIT != 0
}

func (rh *ringbufHeader) isDiscard() bool {
	return rh.Len&unix.BPF_RINGBUF_DISCARD_BIT != 0
}

func (rh *ringbufHeader) dataLen() int {
	return int(rh.Len & ^uint32(unix.BPF_RINGBUF_BUSY_BIT|unix.BPF_RINGBUF_DISCARD_BIT))
}

type Record struct {
	RawSample []byte
}

func readRecord(rd *ringbufEventRing) (r Record, err error) {
	rd.loadConsumer()
	var header ringbufHeader
	err = binary.Read(rd, internal.NativeEndian, &header)
	if err == io.EOF {
		return Record{}, err
	}

	if err != nil {
		return Record{}, fmt.Errorf("can't read event header: %w", err)
	}

	if header.isBusy() {
		// the next sample in the ring is not committed yet so we
		// exit without storing the reader/consumer position
		// and start again from the same position.
		return Record{}, fmt.Errorf("%w", errBusy)
	}

	/* read up to 8 byte alignment */
	dataLenAligned := uint64(internal.Align(header.dataLen(), 8))

	if header.isDiscard() {
		// when the record header indicates that the data should be
		// discarded, we skip it by just updating the consumer position
		// to the next record instead of normal Read() to avoid allocating data
		// and reading/copying from the ring (which normally keeps track of the
		// consumer position).
		rd.skipRead(dataLenAligned)
		rd.storeConsumer()

		return Record{}, fmt.Errorf("%w", errDiscard)
	}

	data := make([]byte, dataLenAligned)

	if _, err := io.ReadFull(rd, data); err != nil {
		return Record{}, fmt.Errorf("can't read sample: %w", err)
	}

	rd.storeConsumer()

	return Record{RawSample: data[:header.dataLen()]}, nil
}

// Reader allows reading bpf_ringbuf_output
// from user space.
type Reader struct {
	poller *epoll.Poller

	// mu protects read/write access to the Reader structure
	mu          sync.Mutex
	ring        *ringbufEventRing
	epollEvents []unix.EpollEvent
}

// NewReader creates a new BPF ringbuf reader.
func NewReader(ringbufMap *ebpf.Map) (*Reader, error) {
	if ringbufMap.Type() != ebpf.RingBuf {
		return nil, fmt.Errorf("invalid Map type: %s", ringbufMap.Type())
	}

	maxEntries := int(ringbufMap.MaxEntries())
	if maxEntries == 0 || (maxEntries&(maxEntries-1)) != 0 {
		return nil, fmt.Errorf("ringbuffer map size %d is zero or not a power of two", maxEntries)
	}

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	if err := poller.Add(ringbufMap.FD(), 0); err != nil {
		poller.Close()
		return nil, err
	}

	ring, err := newRingBufEventRing(ringbufMap.FD(), maxEntries)
	if err != nil {
		poller.Close()
		return nil, fmt.Errorf("failed to create ringbuf ring: %w", err)
	}

	return &Reader{
		poller:      poller,
		ring:        ring,
		epollEvents: make([]unix.EpollEvent, 1),
	}, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
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

	if r.ring != nil {
		r.ring.Close()
		r.ring = nil
	}

	return nil
}

// Read the next record from the BPF ringbuf.
//
// Calling Close interrupts the function.
func (r *Reader) Read() (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ring == nil {
		return Record{}, fmt.Errorf("ringbuffer: %w", ErrClosed)
	}

	for {
		_, err := r.poller.Wait(r.epollEvents)
		if err != nil {
			return Record{}, err
		}

		record, err := readRecord(r.ring)
		if errors.Is(err, errBusy) || errors.Is(err, errDiscard) {
			continue
		}

		return record, err
	}
}
