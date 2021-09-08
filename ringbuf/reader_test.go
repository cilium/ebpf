package ringbuf

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/google/go-cmp/cmp"
)

func TestRingbufReader(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	readerTests := []struct {
		name     string
		messages []int
		want     map[int][]byte
	}{
		{
			name:     "send one short sample",
			messages: []int{5},
			want: map[int][]byte{
				5: {1, 2, 3, 4, 4},
			},
		},
		{
			name:     "send three short samples, the second is discarded",
			messages: []int{5, 10, 15},
			want: map[int][]byte{
				5:  {1, 2, 3, 4, 4},
				15: {1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2},
			},
		},
	}
	for _, tt := range readerTests {
		t.Run(tt.name, func(t *testing.T) {
			prog, events := mustOutputSamplesProg(t, 0, tt.messages...)

			rd, err := NewReader(events)
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

			raw := make(map[int][]byte)

			for len(raw) < len(tt.want) {
				record, err := rd.Read()
				if err != nil {
					t.Fatal("Can't read samples:", err)
				}
				raw[len(record.RawSample)] = record.RawSample
			}

			if diff := cmp.Diff(tt.want, raw); diff != "" {
				t.Errorf("Read samples mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func outputSamplesProg(flags int32, sampleSizes ...int) (*ebpf.Program, *ebpf.Map, error) {
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
		License:      "MIT",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	if err != nil {
		events.Close()
		return nil, nil, err
	}

	return prog, events, nil
}

func mustOutputSamplesProg(tb testing.TB, flags int32, sampleSizes ...int) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	prog, events, err := outputSamplesProg(flags, sampleSizes...)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		prog.Close()
		events.Close()
	})

	return prog, events
}

func TestRingbufReaderClose(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	_, events := mustOutputSamplesProg(t, 0, 5)

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

	// Close should interrupt blocking Read
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errs:
		if !errors.Is(err, ErrClosed) {
			t.Fatal("Read from RingbufReader that got closed does return ErrClosed")
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

	b.ResetTimer()
	b.ReportAllocs()

	for _, bm := range readerBenchmarks {
		b.Run(bm.name, func(b *testing.B) {
			prog, events := mustOutputSamplesProg(b, bm.flags, 80)

			rd, err := NewReader(events)
			if err != nil {
				b.Fatal(err)
			}
			defer rd.Close()

			for i := 0; i < b.N; i++ {
				ret, _, err := prog.Benchmark(make([]byte, 14), 1, nil)
				if err != nil {
					b.Fatal(err)
				} else if errno := syscall.Errno(-int32(ret)); errno != 0 {
					b.Fatal("Expected 0 as return value, got", errno)
				}
				_, err = rd.Read()
				if err != nil {
					b.Fatal("Can't read samples:", err)
				}
			}
		})
	}
}
