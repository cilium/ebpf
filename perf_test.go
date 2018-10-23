package ebpf

import (
	"bytes"
	"fmt"
	"io"
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
	coll, err := LoadCollection("testdata/perf_output.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	rd, err := NewPerfReader(PerfReaderOptions{
		Map:          coll.DetachMap("events"),
		PerCPUBuffer: 4096,
		// This is chosen to notify _after_ the lost sample record
		// has been created.
		Watermark: 4032,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	prog := coll.DetachProgram("create_lost_sample")
	defer prog.Close()

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	for sample := range rd.Samples {
		// Wait for small sample, as an indicator that the reader has processed
		// the lost event.
		if len(sample.Data) == 4 {
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
	numSamples := cap(rd.Samples)*2
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
	go func(){
		rd.FlushAndClose()
		// Should be able to call this multiple times
		rd.FlushAndClose()
		close(done)
	}()

	received := 0
	for _ = range rd.Samples {
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
