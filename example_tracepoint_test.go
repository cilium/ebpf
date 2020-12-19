// +build linux

package ebpf_test

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	ringbuffer "github.com/cilium/ebpf/perf"

	"github.com/elastic/go-perf"
)

// This demonstrates how to attach an eBPF program to a tracepoint.
// The program will be attached to the sys_enter_open syscall and print out the integer
// 123 everytime the sycall is used.
func Example_tracepoint() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "pureGo",
	})
	if err != nil {
		panic(fmt.Errorf("could not create event map: %v\n", err))
	}
	defer events.Close()

	rd, err := ringbuffer.NewReader(events, os.Getpagesize())
	if err != nil {
		panic(fmt.Errorf("could not create event reader: %v", err))
	}
	defer rd.Close()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			record, err := rd.Read()
			if err != nil {
				if ringbuffer.IsClosed(err) {
					return
				}
				panic(fmt.Errorf("could not read from reader: %v", err))
			}
			fmt.Println(record)
		}
	}()

	ins := asm.Instructions{
		// store the integer 123 at FP[-8]
		asm.Mov.Imm(asm.R2, 123),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.Word),

		// load registers with arguments for call of FnPerfEventOutput
		asm.LoadMapPtr(asm.R2, events.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -8),
		asm.Mov.Imm(asm.R5, 4),

		// call FnPerfEventOutput
		asm.FnPerfEventOutput.Call(),

		// set exit code to 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "trace_open",
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: ins,
	})
	if err != nil {
		panic(fmt.Errorf("could not create new ebpf program: %v", err))
	}
	defer prog.Close()

	ga := new(perf.Attr)
	gtp := perf.Tracepoint("syscalls", "sys_enter_open")
	if err := gtp.Configure(ga); err != nil {
		panic(fmt.Errorf("failed to configure tracepoint: %v", err))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	openTracepoint, err := perf.Open(ga, perf.CallingThread, perf.AnyCPU, nil)
	if err != nil {
		panic(fmt.Errorf("failed to open perf event on tracepoint: %v", err))
	}
	defer openTracepoint.Close()

	if err := openTracepoint.SetBPF(uint32(prog.FD())); err != nil {
		panic(fmt.Errorf("failed to attach eBPF to tracepoint: %v", err))
	}

	<-ctx.Done()
}
