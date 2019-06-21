package ebpf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

func TestPerfReader(t *testing.T) {
	coll, err := LoadCollection("testdata/perf_output.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	rd, err := NewPerfReader(PerfReaderOptions{
		Map:          coll.DetachMap("events"),
		PerCPUBuffer: 4096,
		Watermark:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	prog := coll.DetachProgram("output_single")
	defer prog.Close()

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	sample := <-rd.Samples
	want := []byte{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(sample.Data, want) {
		t.Log(sample.Data)
		t.Error("Sample doesn't match expected output")
	}
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
	const eventSize = 192

	pageSize := os.Getpagesize()

	remainder := pageSize % eventSize
	if !(remainder == 64 || remainder == 128) {
		// Page size isn't 2^(6+m), m >= 0
		t.Fatal("unsupported page size:", pageSize)
	}

	coll, err := LoadCollection("testdata/perf_output.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	rd, err := NewPerfReader(PerfReaderOptions{
		Map:          coll.DetachMap("events"),
		PerCPUBuffer: pageSize,
		// Notify 30 bytes _after_ the last output_large event that can fit in one page,
		// ie after the lost record is written, and when the output_small event is written.
		Watermark: pageSize - (remainder - 30),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	prog := coll.DetachProgram("output_large")
	defer prog.Close()

	// Fill the ring with the maximum number of output_large events that will fit,
	// and generate a lost event by writing an additional event.
	ret, _, err := prog.Benchmark(make([]byte, 14), (pageSize/eventSize)+1)
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	// Generate a small event to trigger the lost record
	prog = coll.DetachProgram("output_single")
	defer prog.Close()

	ret, _, err = prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	// Check we received all the samples
	for sample := range rd.Samples {
		// Wait for the small sample, as an indicator that the reader has processed
		// the lost event.
		if len(sample.Data) == 12 {
			break
		}
	}

	if lost := rd.LostSamples(); lost != 1 {
		t.Error("Expected 1 lost sample, got", lost)
	}
}

func TestPerfReaderClose(t *testing.T) {
	coll, err := LoadCollection("testdata/perf_output.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	rd, err := NewPerfReader(PerfReaderOptions{
		Map:          coll.DetachMap("events"),
		PerCPUBuffer: 4096,
		Watermark:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	prog := coll.DetachProgram("output_single")
	defer prog.Close()

	// more samples than the channel capacity
	for i := 0; i < cap(rd.Samples)*2; i++ {
		ret, _, err := prog.Test(make([]byte, 14))
		if err != nil {
			t.Fatal(err)
		}

		if errno := syscall.Errno(-int32(ret)); errno != 0 {
			t.Fatal("Expected 0 as return value, got", errno)
		}
	}

	// Close shouldn't block on us not reading
	rd.Close()

	// And we should be able to call it multiple times
	rd.Close()
}

func TestPerfReaderFlushAndClose(t *testing.T) {
	coll, err := LoadCollection("testdata/perf_output.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	rd, err := NewPerfReader(PerfReaderOptions{
		Map:          coll.DetachMap("events"),
		PerCPUBuffer: 4096,
		Watermark:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	prog := coll.DetachProgram("output_single")
	defer prog.Close()

	// more samples than the channel capacity
	numSamples := cap(rd.Samples) * 2
	for i := 0; i < numSamples; i++ {
		ret, _, err := prog.Test(make([]byte, 14))
		if err != nil {
			t.Fatal(err)
		}

		if errno := syscall.Errno(-int32(ret)); errno != 0 {
			t.Fatal("Expected 0 as return value, got", errno)
		}
	}

	done := make(chan struct{})
	go func() {
		rd.FlushAndClose()
		// Should be able to call this multiple times
		rd.FlushAndClose()
		close(done)
	}()

	received := 0
	for range rd.Samples {
		received++
	}

	if received != numSamples {
		t.Fatalf("Expected %d samples got %d", numSamples, received)
	}

	<-done
}

func TestRingBuffer(t *testing.T) {
	buf := make([]byte, 2)

	ring := makeRing(2, 0)
	n, err := ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	if n != 2 {
		t.Errorf("Expected to read 2 bytes, got %d", n)
	}
	if !bytes.Equal(buf, []byte{0, 1}) {
		t.Error("Expected [0, 1], got", buf)
	}
	n, err = ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	if n != 0 {
		t.Error("Expected to read 0 bytes, got", n)
	}

	// Wrapping read
	ring = makeRing(2, 1)
	n, err = io.ReadFull(ring, buf)
	if err != nil {
		t.Error("Error while reading:", err)
	}
	if n != 2 {
		t.Errorf("Expected to read 2 byte, got %d", n)
	}
	if !bytes.Equal(buf, []byte{1, 0}) {
		t.Error("Expected [1, 0], got", buf)
	}
}

func makeRing(size, offset int) *ringReader {
	if size%2 != 0 {
		panic("size must be power of two")
	}

	ring := make([]byte, size)
	for i := range ring {
		ring[i] = byte(i)
	}

	meta := perfEventMeta{
		dataHead: uint64(len(ring) + offset),
		dataTail: uint64(offset),
		dataSize: uint64(len(ring)),
	}

	return newRingReader(&meta, ring)
}

// ExamplePerfReader submits a perf event using BPF,
// and then reads it in user space.
//
// The BPF will look something like this:
//
//    struct map events __section("maps") = {
//      .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//    };
//
//    __section("xdp") int output_single(void *ctx) {
//      unsigned char buf[] = {
//        1, 2, 3, 4, 5
//      };
//
//       return perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &buf[0], 5);
//     }
//
// Also see BPF_F_CTXLEN_MASK if you want to sample packet data
// from SKB or XDP programs.
func ExamplePerfReader() {
	coll, err := LoadCollection("testdata/perf_output.elf")
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	rd, err := NewPerfReader(PerfReaderOptions{
		Map:          coll.DetachMap("events"),
		PerCPUBuffer: 4096,
		// Notify immediately
		Watermark: 1,
	})
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	prog := coll.DetachProgram("output_single")
	defer prog.Close()

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		panic(err)
	}

	if ret != 0 {
		panic("expected 0 return value")
	}

	select {
	case sample := <-rd.Samples:
		// Data is padded with 0 for alignment
		fmt.Println("Sample:", sample.Data)
	case err := <-rd.Error:
		panic(err)
	}

	// Output: Sample: [1 2 3 4 5 0 0 0 0 0 0 0]
}
