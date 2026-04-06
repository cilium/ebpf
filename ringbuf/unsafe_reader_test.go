package ringbuf

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

type testPoller struct{}

func (testPoller) Wait(deadline time.Time) error { return nil }
func (testPoller) Flush() error                  { return nil }
func (testPoller) Close() error                  { return nil }

type testEventRing struct {
	rr *ringReader
}

func (r *testEventRing) size() int {
	return r.rr.size()
}

func (r *testEventRing) AvailableBytes() uint64 {
	return r.rr.AvailableBytes()
}

func (r *testEventRing) readRecordFunc(f func(sample []byte, remaining int, cons uintptr) error) error {
	return r.rr.readRecordFunc(f)
}

func (r *testEventRing) commitRecord(cons uintptr) {
	r.rr.commitRecord(cons)
}

func (r *testEventRing) Close() error {
	return nil
}

func newUnsafeReaderForRecords(t *testing.T, samples ...[]byte) (*UnsafeReader, *uintptr, *uintptr) {
	t.Helper()

	data := make([]byte, 512)
	var (
		prod uintptr
		cons uintptr
	)

	offset := uintptr(0)
	for _, sample := range samples {
		binary.LittleEndian.PutUint32(data[offset:], uint32(len(sample)))
		offset += sys.BPF_RINGBUF_HDR_SZ
		copy(data[offset:offset+uintptr(len(sample))], sample)
		offset += uintptr(internal.Align(len(sample), 8))
	}
	prod = offset

	rr := newRingReader(&cons, &prod, data)
	er := &testEventRing{rr: rr}
	reader := &UnsafeReader{
		poller:     testPoller{},
		ring:       er,
		haveData:   true,
		bufferSize: rr.size(),
	}

	return reader, &cons, &prod
}

func TestUnsafeReaderReadIntoRequiresCommit(t *testing.T) {
	reader, cons, _ := newUnsafeReaderForRecords(t, []byte{1, 2, 3}, []byte{4, 5})

	var rec Record
	err := reader.ReadInto(&rec)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(rec.RawSample, []byte{1, 2, 3}))
	qt.Assert(t, qt.Equals(*cons, uintptr(0)))

	err = reader.ReadInto(&rec)
	qt.Assert(t, qt.ErrorMatches(err, "ringbuffer: previous record must be committed"))

	err = reader.Commit()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(*cons, uintptr(0))))
	firstCons := *cons

	err = reader.ReadInto(&rec)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(rec.RawSample, []byte{4, 5}))
	qt.Assert(t, qt.Equals(*cons, firstCons))

	err = reader.Commit()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(*cons, firstCons)))
}

func TestUnsafeReaderReadFuncAlwaysCommits(t *testing.T) {
	reader, cons, prod := newUnsafeReaderForRecords(t, []byte{1, 2, 3})

	wantErr := errors.New("callback failed")
	remaining, err := reader.ReadFunc(func(sample []byte, remaining int) error {
		qt.Assert(t, qt.DeepEquals(sample, []byte{1, 2, 3}))
		qt.Assert(t, qt.Equals(remaining, 0))
		return wantErr
	})

	qt.Assert(t, qt.Equals(remaining, 0))
	qt.Assert(t, qt.Equals(err, wantErr))
	qt.Assert(t, qt.Equals(*cons, *prod))
}

func TestUnsafeReaderCommitWithoutPendingRecord(t *testing.T) {
	reader, _, _ := newUnsafeReaderForRecords(t)
	err := reader.Commit()
	qt.Assert(t, qt.ErrorMatches(err, "ringbuffer: no pending record to commit"))
}
