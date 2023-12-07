package ringbuf

import (
	"errors"
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
	"github.com/google/go-cmp/cmp"
)

type sampleMessage struct {
	size  int
	flags int32
}

func TestMain(m *testing.M) {
	fdtrace.TestMain(m)
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
			messages: []sampleMessage{{size: 5}, {size: 10}, {size: 15}},
			want: map[int][]byte{
				5:  {1, 2, 3, 4, 4},
				15: {1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2},
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

			if uint32(rd.BufferSize()) != 2*events.MaxEntries() {
				t.Errorf("expected %d BufferSize, got %d", events.MaxEntries(), rd.BufferSize())
			}

			ret, _, err := prog.Test(internal.EmptyBPFContext)
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

func outputSamplesProg(sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map, error) {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		return nil, nil, err
	}

	var maxSampleSize int
	for _, sampleMessage := range sampleMessages {
		if sampleMessage.size > maxSampleSize {
			maxSampleSize = sampleMessage.size
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

	for sampleIdx, sampleMessage := range sampleMessages {
		insns = append(insns,
			asm.LoadMapPtr(asm.R1, events.FD()),
			asm.Mov.Imm(asm.R2, int32(sampleMessage.size)),
			asm.Mov.Imm(asm.R3, int32(0)),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.Mov.Reg(asm.R5, asm.R0),
		)
		for i := 0; i < sampleMessage.size; i++ {
			insns = append(insns,
				asm.LoadMem(asm.R4, asm.RFP, int16(i+1)*-1, asm.Byte),
				asm.StoreMem(asm.R5, int16(i), asm.R4, asm.Byte),
			)
		}

		// discard every even sample
		if sampleIdx&1 != 0 {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, sampleMessage.flags),
				asm.FnRingbufDiscard.Call(),
			)
		} else {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, sampleMessage.flags),
				asm.FnRingbufSubmit.Call(),
			)
		}
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(0)).WithSymbol("exit"),
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

func mustOutputSamplesProg(tb testing.TB, sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	prog, events, err := outputSamplesProg(sampleMessages...)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		prog.Close()
		events.Close()
	})

	return prog, events
}

func TestReaderBlocking(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF ring buffer")

	prog, events := mustOutputSamplesProg(t, sampleMessage{size: 5, flags: 0})
	ret, _, err := prog.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

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
		sampleMessage{size: 5, flags: unix.BPF_RB_NO_WAKEUP}, // Read after timeout
		sampleMessage{size: 6, flags: unix.BPF_RB_NO_WAKEUP}, // Discard
		sampleMessage{size: 7, flags: unix.BPF_RB_NO_WAKEUP}) // Read won't block

	rd, err := NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	ret, _, err := prog.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	rd.SetDeadline(time.Now())
	record, err := rd.Read()

	if err != nil {
		t.Error("Expected no error from first Read, got:", err)
	}
	if len(record.RawSample) != 5 {
		t.Errorf("Expected to read 5 bytes bot got %d", len(record.RawSample))
	}

	record, err = rd.Read()

	if err != nil {
		t.Error("Expected no error from second Read, got:", err)
	}
	if len(record.RawSample) != 7 {
		t.Errorf("Expected to read 7 bytes bot got %d", len(record.RawSample))
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

	buf := internal.EmptyBPFContext

	b.ResetTimer()
	b.ReportAllocs()

	var rec Record
	for i := 0; i < b.N; i++ {
		ret, _, err := prog.Test(buf)
		if err != nil {
			b.Fatal(err)
		} else if errno := syscall.Errno(-int32(ret)); errno != 0 {
			b.Fatal("Expected 0 as return value, got", errno)
		}

		if err := rd.ReadInto(&rec); err != nil {
			b.Fatal("Can't read samples:", err)
		}
	}
}
