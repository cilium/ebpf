package perf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/testutils/fdtrace"
	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

var (
	readTimeout = 250 * time.Millisecond
)

func TestMain(m *testing.M) {
	fdtrace.TestMain(m)
}

func TestPerfReader(t *testing.T) {
	events := perfEventArray(t)

	rd, err := NewReader(events, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	outputSamples(t, events, 5)

	checkRecord(t, rd)

	rd.SetDeadline(time.Now().Add(4 * time.Millisecond))
	_, err = rd.Read()
	qt.Assert(t, errors.Is(err, os.ErrDeadlineExceeded), qt.IsTrue, qt.Commentf("expected os.ErrDeadlineExceeded"))
}

func TestReaderSetDeadline(t *testing.T) {
	events := perfEventArray(t)

	rd, err := NewReader(events, 4096)
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

func outputSamples(tb testing.TB, events *ebpf.Map, sampleSizes ...byte) {
	prog := outputSamplesProg(tb, events, sampleSizes...)

	ret, _, err := prog.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(tb, err)
	if err != nil {
		tb.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		tb.Fatal("Expected 0 as return value, got", errno)
	}
}

// outputSamplesProg creates a program which submits a series of samples to a PerfEventArray.
//
// The format of each sample is:
//
//	index:   0    1    2    3    ... size - 1
//	content: size id   0xff 0xff ... 0xff     [padding]
//
// padding is an implementation detail of the perf buffer and 1-7 bytes long. The
// contents are undefined.
func outputSamplesProg(tb testing.TB, events *ebpf.Map, sampleSizes ...byte) *ebpf.Program {
	tb.Helper()

	// Requires at least 4.9 (0515e5999a46 "bpf: introduce BPF_PROG_TYPE_PERF_EVENT program type")
	testutils.SkipOnOldKernel(tb, "4.9", "perf events support")

	const bpfFCurrentCPU = 0xffffffff

	var maxSampleSize byte
	for _, sampleSize := range sampleSizes {
		if sampleSize < 2 {
			tb.Fatalf("Sample size %d is too small to contain size and counter", sampleSize)
		}
		if sampleSize > maxSampleSize {
			maxSampleSize = sampleSize
		}
	}

	// Fill a buffer on the stack, and stash context somewhere
	insns := asm.Instructions{
		asm.LoadImm(asm.R0, ^int64(0), asm.DWord),
		asm.Mov.Reg(asm.R9, asm.R1),
	}

	bufDwords := int(maxSampleSize/8) + 1
	for i := 0; i < bufDwords; i++ {
		insns = append(insns,
			asm.StoreMem(asm.RFP, int16(i+1)*-8, asm.R0, asm.DWord),
		)
	}

	for i, sampleSize := range sampleSizes {
		insns = append(insns,
			// Restore stashed context.
			asm.Mov.Reg(asm.R1, asm.R9),
			// map
			asm.LoadMapPtr(asm.R2, events.FD()),
			// flags
			asm.LoadImm(asm.R3, bpfFCurrentCPU, asm.DWord),
			// buffer
			asm.Mov.Reg(asm.R4, asm.RFP),
			asm.Add.Imm(asm.R4, int32(bufDwords*-8)),
			// buffer[0] = size
			asm.StoreImm(asm.R4, 0, int64(sampleSize), asm.Byte),
			// buffer[1] = i
			asm.StoreImm(asm.R4, 1, int64(i&math.MaxUint8), asm.Byte),
			// size
			asm.Mov.Imm(asm.R5, int32(sampleSize)),
			asm.FnPerfEventOutput.Call(),
		)
	}

	insns = append(insns, asm.Return())

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "GPL",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { prog.Close() })

	return prog
}

func checkRecord(tb testing.TB, rd *Reader) (id int) {
	tb.Helper()

	rec, err := rd.Read()
	qt.Assert(tb, err, qt.IsNil)

	qt.Assert(tb, rec.CPU >= 0, qt.IsTrue, qt.Commentf("Record has invalid CPU number"))

	size := int(rec.RawSample[0])
	qt.Assert(tb, len(rec.RawSample) >= size, qt.IsTrue, qt.Commentf("RawSample is at least size bytes"))

	for i, v := range rec.RawSample[2:size] {
		qt.Assert(tb, v, qt.Equals, byte(0xff), qt.Commentf("filler at position %d should match", i+2))
	}

	// padding is ignored since it's value is undefined.

	return int(rec.RawSample[1])
}

func TestPerfReaderLostSample(t *testing.T) {
	// To generate a lost sample perf record:
	//
	// 1. Fill the perf ring buffer almost completely, with the output_large program.
	//    The buffer is sized in number of pages, which are architecture dependant.
	//
	// 2. Write an extra event that doesn't fit in the space remaining.
	//
	// 3. Write a smaller event that does fit, with output_single program.
	//    Lost sample records are generated opportunistically, when the kernel
	//    is writing an event and realizes that there were events lost previously.
	//
	// The event size is hardcoded in the test BPF programs, there's no way
	// to parametrize it without rebuilding the programs.
	//
	// The event size needs to be selected so that, for any page size, there are at least
	// 48 bytes left in the perf ring page after filling it with a whole number of events:
	//
	//  - PERF_RECORD_LOST: 8 (perf_event_header) + 16 (PERF_RECORD_LOST)
	//
	//  - output_single: 8 (perf_event_header) + 4 (size) + 5 (payload) + 7 (padding to 64bits)
	//
	// By selecting an event size of the form 2^n + 2^(n+1), for any page size 2^(n+m), m >= 0,
	// the number of bytes left, x, after filling a page with a whole number of events is:
	//
	//                     2^(n+m)                            2^n * 2^m
	//  x = 2^n * frac(---------------) <=> x = 2^n * frac(---------------)
	//                  2^n + 2^(n+1)                       2^n + 2^n * 2
	//
	//                                                        2^n * 2^m
	//                                  <=> x = 2^n * frac(---------------)
	//                                                      2^n * (1 + 2)
	//
	//                                                      2^m
	//                                  <=> x = 2^n * frac(-----)
	//                                                       3
	//
	//                                                1                2
	//                                  <=> x = 2^n * -  or  x = 2^n * -
	//                                                3                3
	//
	// Selecting n = 6, we have:
	//
	//  x = 64  or  x = 128, no matter the page size 2^(6+m)
	//
	//  event size = 2^6 + 2^7 = 192
	//
	// Accounting for perf headers, output_large uses a 180 byte payload:
	//
	//  8 (perf_event_header) + 4 (size) + 180 (payload)
	const (
		eventSize = 192
	)

	var (
		pageSize  = os.Getpagesize()
		maxEvents = (pageSize / eventSize)
	)
	if remainder := pageSize % eventSize; remainder != 64 && remainder != 128 {
		// Page size isn't 2^(6+m), m >= 0
		t.Fatal("unsupported page size:", pageSize)
	}

	var sampleSizes []byte
	// Fill the ring with the maximum number of output_large events that will fit,
	// and generate a lost event by writing an additional event.
	for i := 0; i < maxEvents+1; i++ {
		sampleSizes = append(sampleSizes, 180)
	}

	// Generate a small event to trigger the lost record
	sampleSizes = append(sampleSizes, 5)

	events := perfEventArray(t)

	rd, err := NewReader(events, pageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	outputSamples(t, events, sampleSizes...)

	for range sampleSizes {
		record, err := rd.Read()
		if err != nil {
			t.Fatal(err)
		}

		if record.RawSample == nil && record.LostSamples != 1 {
			t.Fatal("Expected a record with LostSamples 1, got", record.LostSamples)
		}
	}
}

func TestPerfReaderOverwritable(t *testing.T) {
	// Smallest buffer size.
	pageSize := os.Getpagesize()

	const sampleSize = math.MaxUint8

	// Account for perf header (8) and size (4), align to 8 bytes as perf does.
	realSampleSize := internal.Align(sampleSize+8+4, 8)
	maxEvents := pageSize / realSampleSize

	var sampleSizes []byte
	for i := 0; i < maxEvents; i++ {
		sampleSizes = append(sampleSizes, sampleSize)
	}
	// Append an extra sample that will overwrite the first sample.
	sampleSizes = append(sampleSizes, sampleSize)

	events := perfEventArray(t)

	rd, err := NewReaderWithOptions(events, pageSize, ReaderOptions{Overwritable: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	_, err = rd.Read()
	qt.Assert(t, err, qt.ErrorIs, errMustBePaused)

	outputSamples(t, events, sampleSizes...)

	qt.Assert(t, rd.Pause(), qt.IsNil)
	rd.SetDeadline(time.Now())

	nextID := maxEvents
	for i := 0; i < maxEvents; i++ {
		id := checkRecord(t, rd)
		qt.Assert(t, id, qt.Equals, nextID)
		nextID--
	}
}

func TestPerfReaderOverwritableEmpty(t *testing.T) {
	events := perfEventArray(t)
	rd, err := NewReaderWithOptions(events, os.Getpagesize(), ReaderOptions{Overwritable: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	err = rd.Pause()
	if err != nil {
		t.Fatal(err)
	}

	rd.SetDeadline(time.Now().Add(4 * time.Millisecond))
	_, err = rd.Read()
	qt.Assert(t, errors.Is(err, os.ErrDeadlineExceeded), qt.IsTrue, qt.Commentf("expected os.ErrDeadlineExceeded"))

	err = rd.Resume()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPerfReaderClose(t *testing.T) {
	events := perfEventArray(t)

	rd, err := NewReader(events, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	errs := make(chan error, 1)
	waiting := make(chan struct{})
	go func() {
		close(waiting)
		_, err := rd.Read()
		errs <- err
	}()

	<-waiting

	// Close should interrupt Read
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-errs:
	case <-time.After(time.Second):
		t.Fatal("Close doesn't interrupt Read")
	}

	// And we should be able to call it multiple times
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := rd.Read(); err == nil {
		t.Fatal("Read on a closed PerfReader doesn't return an error")
	}
}

func TestCreatePerfEvent(t *testing.T) {
	fd, err := createPerfEvent(0, 1, false)
	if err != nil {
		t.Fatal("Can't create perf event:", err)
	}
	unix.Close(fd)
}

func TestReadRecord(t *testing.T) {
	var buf bytes.Buffer

	err := binary.Write(&buf, internal.NativeEndian, &perfEventHeader{})
	if err != nil {
		t.Fatal(err)
	}

	var rec Record
	err = readRecord(&buf, &rec, make([]byte, perfEventHeaderSize), false)
	if !IsUnknownEvent(err) {
		t.Error("readRecord should return unknown event error, got", err)
	}
}

func TestPause(t *testing.T) {
	t.Parallel()

	events := perfEventArray(t)

	rd, err := NewReader(events, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	// Reader is already unpaused by default. It should be idempotent.
	if err = rd.Resume(); err != nil {
		t.Fatal(err)
	}

	// Write a sample. The reader should read it.
	prog := outputSamplesProg(t, events, 5)
	ret, _, err := prog.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil || ret != 0 {
		t.Fatal("Can't write sample")
	}
	if _, err := rd.Read(); err != nil {
		t.Fatal(err)
	}

	// Pause. No notification should trigger.
	if err = rd.Pause(); err != nil {
		t.Fatal(err)
	}
	errChan := make(chan error, 1)
	go func() {
		// Read one notification then send any errors and exit.
		_, err := rd.Read()
		errChan <- err
	}()
	ret, _, err = prog.Test(internal.EmptyBPFContext)
	if err == nil && ret == 0 {
		t.Fatal("Unexpectedly wrote sample while paused")
	} // else Success
	select {
	case err := <-errChan:
		// Failure: Pause was unsuccessful.
		t.Fatalf("received notification on paused reader: %s", err)
	case <-time.After(readTimeout):
		// Success
	}

	// Pause should be idempotent.
	if err = rd.Pause(); err != nil {
		t.Fatal(err)
	}

	// Resume. Now notifications should continue.
	if err = rd.Resume(); err != nil {
		t.Fatal(err)
	}
	ret, _, err = prog.Test(internal.EmptyBPFContext)
	if err != nil || ret != 0 {
		t.Fatal("Can't write sample")
	}
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatal(err)
		} // else Success
	case <-time.After(readTimeout):
		t.Fatal("timed out waiting for notification after resume")
	}

	if err = rd.Close(); err != nil {
		t.Fatal(err)
	}

	// Pause/Resume after close should be no-op.
	err = rd.Pause()
	qt.Assert(t, err, qt.Not(qt.Equals), ErrClosed, qt.Commentf("returns unwrapped ErrClosed"))
	qt.Assert(t, errors.Is(err, ErrClosed), qt.IsTrue, qt.Commentf("doesn't wrap ErrClosed"))

	err = rd.Resume()
	qt.Assert(t, err, qt.Not(qt.Equals), ErrClosed, qt.Commentf("returns unwrapped ErrClosed"))
	qt.Assert(t, errors.Is(err, ErrClosed), qt.IsTrue, qt.Commentf("doesn't wrap ErrClosed"))
}

func BenchmarkReader(b *testing.B) {
	events := perfEventArray(b)
	prog := outputSamplesProg(b, events, 80)

	rd, err := NewReader(events, 4096)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	buf := internal.EmptyBPFContext

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ret, _, err := prog.Test(buf)
		if err != nil {
			b.Fatal(err)
		} else if errno := syscall.Errno(-int32(ret)); errno != 0 {
			b.Fatal("Expected 0 as return value, got", errno)
		}

		if _, err = rd.Read(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadInto(b *testing.B) {
	events := perfEventArray(b)
	prog := outputSamplesProg(b, events, 80)

	rd, err := NewReader(events, 4096)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	buf := internal.EmptyBPFContext

	b.ResetTimer()
	b.ReportAllocs()

	var rec Record
	for i := 0; i < b.N; i++ {
		// NB: Submitting samples into the perf event ring dominates
		// the benchmark time unfortunately.
		ret, _, err := prog.Test(buf)
		if err != nil {
			b.Fatal(err)
		} else if errno := syscall.Errno(-int32(ret)); errno != 0 {
			b.Fatal("Expected 0 as return value, got", errno)
		}

		if err := rd.ReadInto(&rec); err != nil {
			b.Fatal(err)
		}
	}
}

// This exists just to make the example below nicer.
func bpfPerfEventOutputProgram() (*ebpf.Program, *ebpf.Map) {
	return nil, nil
}

// ExamplePerfReader submits a perf event using BPF,
// and then reads it in user space.
//
// The BPF will look something like this:
//
//	struct map events __section("maps") = {
//	  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//	};
//
//	__section("xdp") int output_single(void *ctx) {
//	  unsigned char buf[] = {
//	    1, 2, 3, 4, 5
//	  };
//
//	   return perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &buf[0], 5);
//	 }
//
// Also see BPF_F_CTXLEN_MASK if you want to sample packet data
// from SKB or XDP programs.
func ExampleReader() {
	prog, events := bpfPerfEventOutputProgram()
	defer prog.Close()
	defer events.Close()

	rd, err := NewReader(events, 4096)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	// Writes out a sample with content 1,2,3,4,4
	ret, _, err := prog.Test(internal.EmptyBPFContext)
	if err != nil || ret != 0 {
		panic("Can't write sample")
	}

	record, err := rd.Read()
	if err != nil {
		panic(err)
	}

	// Data is padded with 0 for alignment
	fmt.Println("Sample:", record.RawSample)
}

// ReadRecord allows reducing memory allocations.
func ExampleReader_ReadInto() {
	prog, events := bpfPerfEventOutputProgram()
	defer prog.Close()
	defer events.Close()

	rd, err := NewReader(events, 4096)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	for i := 0; i < 2; i++ {
		// Write out two samples
		ret, _, err := prog.Test(internal.EmptyBPFContext)
		if err != nil || ret != 0 {
			panic("Can't write sample")
		}
	}

	var rec Record
	for i := 0; i < 2; i++ {
		if err := rd.ReadInto(&rec); err != nil {
			panic(err)
		}

		fmt.Println("Sample:", rec.RawSample[:5])
	}
}

func perfEventArray(tb testing.TB) *ebpf.Map {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { events.Close() })
	return events
}
