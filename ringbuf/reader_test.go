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
	"github.com/cilium/ebpf/internal/unix"
)

func TestRingbufReader(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, false, 5)
	defer prog.Close()
	defer events.Close()

	rd, err := NewReaderWithOptions(events, ReaderOptions{pollTimeout: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	ret, _, err := prog.Test(make([]byte, 14))
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

func outputSamplesProg(noWakeup bool, sampleSizes ...int) (*ebpf.Program, *ebpf.Map, error) {
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

	flags := int32(0)
	if noWakeup {
		flags = unix.BPF_RB_NO_WAKEUP
	}

	for sampleIdx, sampleSize := range sampleSizes {
		insns = append(insns,
			asm.LoadMapPtr(asm.R1, events.FD()),
			asm.Mov.Imm(asm.R2, int32(sampleSize)),
			asm.Mov.Imm(asm.R3, int32(0)),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.Mov.Reg(asm.R5, asm.R0),
		)
		for i := 0; i < sampleSize; i++ {
			insns = append(insns,
				asm.LoadMem(asm.R4, asm.RFP, int16(i+1)*-1, asm.Byte),
				asm.StoreMem(asm.R5, int16(i), asm.R4, asm.Byte),
			)
		}

		// discard every even sample
		if sampleIdx&1 != 0 {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, flags),
				asm.FnRingbufDiscard.Call(),
			)
		} else {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, flags),
				asm.FnRingbufSubmit.Call(),
			)
		}
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(0)).Sym("exit"),
		asm.Return(),
	)

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

func mustOutputSamplesProg(tb testing.TB, noWakeup bool, sampleSizes ...int) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	prog, events, err := outputSamplesProg(noWakeup, sampleSizes...)
	if err != nil {
		tb.Fatal(err)
	}

	return prog, events
}

func TestRingbufReaderClose(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, false, 5)
	defer prog.Close()
	defer events.Close()

	rd, err := NewReaderWithOptions(events, ReaderOptions{pollTimeout: -1})
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

	// Close should interrupt blocking Read
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
		t.Fatal("Read on a closed RingbufReader doesn't return an error")
	}
}

func BenchmarkReader(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(b, false, 80)
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
func bpfRingbufEventOutputProgram() (*ebpf.Program, *ebpf.Map) {
	prog, events, err := outputSamplesProg(false, 5)
	if err != nil {
		panic(err)
	}
	return prog, events
}

// ExampleReader submits a ringbuf event using BPF,
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
//        1, 2, 3, 4, 4
//      };
//
//      ptr = bpf_ringbuf_reserve(&events, 5, 0);
//      if !ptr
//          goto exit;
//
//      for (i = 0; i < 5; i++)
//         ptr[i] = buf[i];
//
//      exit:
//      bpf_ringbuf_submit(ptr, 0);
//      return 0;
//     }
func ExampleReader() {
	prog, events := bpfRingbufEventOutputProgram()
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

	fmt.Println("Sample:", record.RawSample)
}
