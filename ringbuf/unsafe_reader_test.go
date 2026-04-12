package ringbuf

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestUnsafeReaderSingle(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, sampleMessage{size: 5})

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	mustRun(t, prog)

	var rec UnsafeRecord
	token, err := rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(rec.RawSample), 5))
	qt.Assert(t, qt.DeepEquals(rec.RawSample, []byte{1, 2, 3, 4, 4}))

	rd.Commit(token)
	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))
}

func TestUnsafeReaderMultiWithDiscards(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5},
		sampleMessage{size: 10, discard: true},
		sampleMessage{size: 15},
	)

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	mustRun(t, prog)

	var rec UnsafeRecord

	tok1, err := rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(rec.RawSample), 5))

	tok2, err := rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(rec.RawSample), 15))

	qt.Assert(t, qt.Not(qt.Equals(rd.AvailableBytes(), 0)))

	rd.Commit(tok1)
	rd.Commit(tok2)
	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))
}

func TestUnsafeReaderCommitOrdering(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5},
		sampleMessage{size: 7},
		sampleMessage{size: 9},
	)

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	mustRun(t, prog)

	var rec UnsafeRecord
	tok1, err := rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	tok2, err := rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	tok3, err := rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))

	// Commit out of order: tok2 first, then tok3. Consumer should not advance
	// because tok1 is still outstanding.
	rd.Commit(tok2)
	qt.Assert(t, qt.Not(qt.Equals(rd.AvailableBytes(), 0)))

	rd.Commit(tok3)
	qt.Assert(t, qt.Not(qt.Equals(rd.AvailableBytes(), 0)))

	// Commit tok1: now all three are contiguously committed, consumer advances.
	rd.Commit(tok1)
	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))
}

func TestUnsafeReaderCommitAll(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5},
		sampleMessage{size: 7},
	)

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	mustRun(t, prog)

	var rec UnsafeRecord
	_, err = rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	_, err = rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Not(qt.Equals(rd.AvailableBytes(), 0)))

	rd.CommitAll()
	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))
}

func TestUnsafeReaderCommitAllNoOp(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	_, events := mustOutputSamplesProg(t, sampleMessage{size: 5})

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	rd.CommitAll()
}

func TestUnsafeReaderReadFunc(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, sampleMessage{size: 5})

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	mustRun(t, prog)

	var got []byte
	err = rd.ReadFunc(func(data []byte) {
		got = make([]byte, len(data))
		copy(got, data)
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(got, []byte{1, 2, 3, 4, 4}))
	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))
}

func TestUnsafeReaderDeadline(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	_, events := mustOutputSamplesProg(t, sampleMessage{size: 5})

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	rd.SetDeadline(time.Now().Add(-time.Second))

	var rec UnsafeRecord
	_, err = rd.Read(&rec)
	qt.Assert(t, qt.ErrorIs(err, os.ErrDeadlineExceeded))
}

func TestUnsafeReaderClose(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	_, events := mustOutputSamplesProg(t, sampleMessage{size: 5})

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(rd.Close()))

	var rec UnsafeRecord
	_, err = rd.Read(&rec)
	qt.Assert(t, qt.ErrorIs(err, ErrClosed))

	qt.Assert(t, qt.IsNil(rd.Close()))
}

func TestUnsafeReaderBlocking(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, sampleMessage{size: 5})

	mustRun(t, prog)

	rd, err := NewUnsafeReader(events)
	qt.Assert(t, qt.IsNil(err))
	defer rd.Close()

	var rec UnsafeRecord
	_, err = rd.Read(&rec)
	qt.Assert(t, qt.IsNil(err))
	rd.CommitAll()

	errs := make(chan error, 1)
	go func() {
		_, err := rd.Read(&rec)
		errs <- err
	}()

	select {
	case err := <-errs:
		t.Fatal("Read returns error instead of blocking:", err)
	case <-time.After(100 * time.Millisecond):
	}

	qt.Assert(t, qt.IsNil(rd.Close()))

	select {
	case err := <-errs:
		if !errors.Is(err, ErrClosed) {
			t.Fatal("Expected os.ErrClosed from interrupted Read, got:", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close doesn't interrupt Read")
	}
}

func BenchmarkUnsafeReader(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(b, sampleMessage{size: 80})

	rd, err := NewUnsafeReader(events)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	b.ReportAllocs()

	var rec UnsafeRecord
	for b.Loop() {
		b.StopTimer()
		mustRun(b, prog)
		b.StartTimer()

		if _, err := rd.Read(&rec); err != nil {
			b.Fatal(err)
		}
		rd.CommitAll()
	}
}

func BenchmarkUnsafeReaderReadFunc(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(b, sampleMessage{size: 80})

	rd, err := NewUnsafeReader(events)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		mustRun(b, prog)
		b.StartTimer()

		if err := rd.ReadFunc(func(data []byte) {}); err != nil {
			b.Fatal(err)
		}
	}
}
