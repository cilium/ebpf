package ringbuf

import (
	"errors"
	"os"
	"testing"
	"time"

	"iter"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/testutils/testmain"
)

type sampleMessage struct {
	size    int
	flags   int32
	discard bool
}

func TestMain(m *testing.M) {
	testmain.Run(m)
}

func TestRingbufReader(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	readerTests := []struct {
		name     string
		messages []sampleMessage
		want     map[int][]byte
	}{
		{
			name:     "send one short sample",
			messages: []sampleMessage{{size: 5}},
			want: map[int][]byte{
				5: {1, 2, 3, 4, 4},
			},
		},
		{
			name:     "send three short samples, the second is discarded",
			messages: []sampleMessage{{size: 5}, {size: 10, discard: true}, {size: 15}},
			want: map[int][]byte{
				5:  {1, 2, 3, 4, 4},
				15: {1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2},
			},
		},
		{
			name:     "send five samples, every even is discarded",
			messages: []sampleMessage{{size: 5}, {size: 10, discard: true}, {size: 15}, {size: 20, discard: true}, {size: 25}},
			want: map[int][]byte{
				5:  {1, 2, 3, 4, 4},
				15: {1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2},
				25: {1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2, 1, 1},
			},
		},
	}
	for _, tt := range readerTests {
		t.Run(tt.name, func(t *testing.T) {
			prog, events := mustOutputSamplesProg(t, tt.messages...)

			rd, err := NewReader(events)
			if err != nil {
				t.Fatal(err)
			}
			defer rd.Close()

			qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))

			if uint32(rd.BufferSize()) != events.MaxEntries() {
				t.Errorf("expected %d BufferSize, got %d", events.MaxEntries(), rd.BufferSize())
			}

			opts := &ebpf.RunOptions{
				Data: internal.EmptyBPFContext,
			}

			if platform.IsWindows {
				opts.Context = make([]byte, 32)
			}

			mustRun(t, prog)

			var avail int
			for _, m := range tt.messages {
				avail += ringbufHeaderSize + internal.Align(m.size, 8)
			}
			qt.Assert(t, qt.Equals(rd.AvailableBytes(), avail))

			raw := make(map[int][]byte)

			for len(raw) < len(tt.want) {
				record, err := rd.Read()
				if err != nil {
					t.Fatal("Can't read samples:", err)
				}
				raw[len(record.RawSample)] = record.RawSample
				if len(raw) == len(tt.want) {
					if record.Remaining != 0 {
						t.Errorf("expected 0 Remaining, got %d", record.Remaining)
					}
				} else {
					if record.Remaining == 0 {
						t.Error("expected non-zero Remaining, got 0")
					}
				}
			}

			if diff := cmp.Diff(tt.want, raw); diff != "" {
				t.Errorf("Read samples mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReaderBlocking(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, sampleMessage{size: 5, flags: 0})

	mustRun(t, prog)

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	if _, err := rd.Read(); err != nil {
		t.Fatal("Can't read first sample:", err)
	}

	errs := make(chan error, 1)
	go func() {
		_, err := rd.Read()
		errs <- err
	}()

	select {
	case err := <-errs:
		t.Fatal("Read returns error instead of blocking:", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Close should interrupt blocking Read
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errs:
		if !errors.Is(err, ErrClosed) {
			t.Fatal("Expected os.ErrClosed from interrupted Read, got:", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close doesn't interrupt Read")
	}

	// And we should be able to call it multiple times
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := rd.Read(); !errors.Is(err, ErrClosed) {
		t.Fatal("Second Read on a closed RingbufReader doesn't return ErrClosed")
	}
}

func TestReaderNoWakeup(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5, flags: sys.BPF_RB_NO_WAKEUP}, // Read after timeout
		sampleMessage{size: 7, flags: sys.BPF_RB_NO_WAKEUP}, // Read won't block
	)

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))

	mustRun(t, prog)

	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 2*16))

	rd.SetDeadline(time.Now())
	record, err := rd.Read()

	if err != nil {
		t.Error("Expected no error from first Read, got:", err)
	}
	if len(record.RawSample) != 5 {
		t.Errorf("Expected to read 5 bytes but got %d", len(record.RawSample))
	}

	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 1*16))

	record, err = rd.Read()

	if err != nil {
		t.Error("Expected no error from second Read, got:", err)
	}
	if len(record.RawSample) != 7 {
		t.Errorf("Expected to read 7 bytes but got %d", len(record.RawSample))
	}

	qt.Assert(t, qt.Equals(rd.AvailableBytes(), 0))

	_, err = rd.Read()
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Expected os.ErrDeadlineExceeded from third Read but got %v", err)
	}
}

func TestReaderFlushPendingEvents(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5, flags: sys.BPF_RB_NO_WAKEUP}, // Read after Flush
		sampleMessage{size: 7, flags: sys.BPF_RB_NO_WAKEUP}, // Read won't block
	)

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	mustRun(t, prog)

	wait := make(chan *Record)
	go func() {
		wait <- nil
		record, err := rd.Read()
		qt.Assert(t, qt.IsNil(err))
		wait <- &record
	}()

	<-wait
	time.Sleep(10 * time.Millisecond)
	err = rd.Flush()
	qt.Assert(t, qt.IsNil(err))

	waitRec := <-wait
	if waitRec == nil {
		t.Error("Expected to read record but got nil")
	}
	if waitRec != nil && len(waitRec.RawSample) != 5 {
		t.Errorf("Expected to read 5 bytes but got %d", len(waitRec.RawSample))
	}

	record, err := rd.Read()

	if err != nil {
		t.Error("Expected no error from second Read, got:", err)
	}
	if len(record.RawSample) != 7 {
		t.Errorf("Expected to read 7 bytes but got %d", len(record.RawSample))
	}

	_, err = rd.Read()
	if !errors.Is(err, ErrFlushed) {
		t.Errorf("Expected ErrFlushed from third Read but got %v", err)
	}
}

func TestReaderSetDeadline(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	_, events := mustOutputSamplesProg(t, sampleMessage{size: 5, flags: 0})
	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	rd.SetDeadline(time.Now().Add(-time.Second))
	if _, err := rd.Read(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("Expected os.ErrDeadlineExceeded from first Read, got:", err)
	}
	if _, err := rd.Read(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("Expected os.ErrDeadlineExceeded from second Read, got:", err)
	}
}

func TestReadAfterClose(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5, flags: 0},
		sampleMessage{size: 5, flags: 0},
	)

	mustRun(t, prog)

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}

	_, err = rd.Read()
	if err != nil {
		t.Error("Expected no error after first Read, got:", err)
	}

	err = rd.Close()
	if err != nil {
		t.Error("Expected no error from Close, got: ", err)
	}

	_, err = rd.Read()
	if err == nil || !errors.Is(err, ErrClosed) {
		t.Error("Expected ErrClosed but got: ", err)
	}
}

func BenchmarkReader(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF ring buffer")

	readerBenchmarks := []struct {
		name  string
		flags int32
	}{
		{
			name: "normal epoll with timeout -1",
		},
	}

	for _, bm := range readerBenchmarks {
		b.Run(bm.name, func(b *testing.B) {
			prog, events := mustOutputSamplesProg(b, sampleMessage{size: 80, flags: bm.flags})

			rd, err := NewReader(events)
			if err != nil {
				b.Fatal(err)
			}
			defer rd.Close()

			b.ReportAllocs()

			for b.Loop() {
				b.StopTimer()
				mustRun(b, prog)
				b.StartTimer()

				_, err = rd.Read()
				if err != nil {
					b.Fatal("Can't read samples:", err)
				}
			}
		})
	}
}

func BenchmarkReadInto(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(b, sampleMessage{size: 80, flags: 0})

	rd, err := NewReader(events)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	b.ReportAllocs()

	var rec Record
	for b.Loop() {
		b.StopTimer()
		mustRun(b, prog)
		b.StartTimer()

		if err := rd.ReadInto(&rec); err != nil {
			b.Fatal("Can't read samples:", err)
		}
	}
}

func TestRecordsIterator(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t,
		sampleMessage{size: 5, flags: 0},
		sampleMessage{size: 7, flags: 0},
	)
	mustRun(t, prog)

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	var seen [][]byte
	for rec, err := range rd.Records() {
		if err != nil {
			t.Fatalf("iteration error: %v", err)
		}
		seen = append(seen, append([]byte(nil), rec.RawSample...))
		if len(seen) == 2 {
			break
		}
	}

	qt.Assert(t, qt.Equals(len(seen), 2))
	qt.Assert(t, qt.DeepEquals(seen[0], []byte{1, 2, 3, 4, 4}))
	qt.Assert(t, qt.DeepEquals(seen[1], []byte{1, 2, 3, 4, 4, 3, 2}))
}

func TestRecordsIteratorCloseStopsWithoutError(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, sampleMessage{size: 5, flags: 0})
	mustRun(t, prog)

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}

	next, stop := iter.Pull2(rd.Records())
	defer stop()

	rec, err, ok := next()
	if !ok {
		t.Fatal("expected first record before Close")
	}
	if err != nil {
		t.Fatalf("unexpected error before Close: %v", err)
	}
	if len(rec.RawSample) == 0 {
		t.Fatal("expected non-empty sample")
	}

	if err := rd.Close(); err != nil {
		t.Fatalf("closing reader: %v", err)
	}

	_, err, ok = next()
	if ok {
		t.Fatal("iterator should stop after Close")
	}
	if err != nil {
		t.Fatalf("iterator returned error after Close: %v", err)
	}
}
