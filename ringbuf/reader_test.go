package ringbuf

import (
	"bytes"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestPerfReader(t *testing.T) {
	prog, events := mustOutputSamplesProg(t, 5)
	defer prog.Close()
	defer events.Close()

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	ret, _, err := prog.Test(make([]byte, 5))
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	record, err := rd.Read()
	if err != nil {
		t.Fatal("Can't read samples:", err)
	}

	want := []byte{1, 2, 3, 4, 4}
	if !bytes.Equal(record.RawSample, want) {
		t.Log(record.RawSample)
		t.Error("Sample doesn't match expected output")
	}
}

func outputSamplesProg(sampleSizes ...int) (*ebpf.Program, *ebpf.Map, error) {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		return nil, nil, err
	}

	var maxSampleSize int
	for _, sampleSize := range sampleSizes {
		if sampleSize > maxSampleSize {
			maxSampleSize = sampleSize
		}
	}

	// Fill a buffer on the stack
	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0x0102030404030201, asm.DWord),
		asm.Mov.Reg(asm.R9, asm.R1),
	}

	bufDwords := (maxSampleSize / 8) + 1
	for i := 0; i < bufDwords; i++ {
		insns = append(insns,
			asm.StoreMem(asm.RFP, int16(i+1)*-8, asm.R0, asm.DWord),
		)
	}

	for _, sampleSize := range sampleSizes {
		insns = append(insns,
			asm.LoadMapPtr(asm.R1, events.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, int32(bufDwords*-8)),
			asm.Mov.Imm(asm.R3, int32(sampleSize)),
			asm.Mov.Imm(asm.R4, int32(0)),
			asm.FnRingbufOutput.Call(),
		)
	}

	insns = append(insns, asm.Return())

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "GPL",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	if err != nil {
		events.Close()
		return nil, nil, err
	}

	return prog, events, nil
}

func mustOutputSamplesProg(tb testing.TB, sampleSizes ...int) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	prog, events, err := outputSamplesProg(sampleSizes...)
	if err != nil {
		tb.Fatal(err)
	}

	return prog, events
}

func TestPerfReaderClose(t *testing.T) {
	prog, events := mustOutputSamplesProg(t, 5)
	defer prog.Close()
	defer events.Close()

	rd, err := NewReader(events)
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

func BenchmarkReader(b *testing.B) {
	prog, events := mustOutputSamplesProg(b, 80)
	defer prog.Close()
	defer events.Close()

	rd, err := NewReader(events)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	buf := make([]byte, 14)

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

// This exists just to make the example below nicer.
func bpfPerfEventOutputProgram() (*ebpf.Program, *ebpf.Map) {
	prog, events, err := outputSamplesProg(5)
	if err != nil {
		panic(err)
	}
	return prog, events
}

// ExamplePerfReader submits a perf event using BPF,
// and then reads it in user space.
//
// The BPF will look something like this:
//
//    struct map events __section("maps") = {
//      .type = BPF_MAP_TYPE_RINGBUF,
//    };
//
//    __section("xdp") int output_single(void *ctx) {
//      unsigned char buf[] = {
//        1, 2, 3, 4, 5
//      };
//
//       return bpf_ringbuf_output(&events, &buf[0], 5, 0);
//     }
//
// Also see BPF_F_CTXLEN_MASK if you want to sample packet data
// from SKB or XDP programs.
func ExampleReader() {
	prog, events := bpfPerfEventOutputProgram()
	defer prog.Close()
	defer events.Close()

	rd, err := NewReader(events)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	// Writes out a sample with content 1,2,3,4,4
	ret, _, err := prog.Test(make([]byte, 14))
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
