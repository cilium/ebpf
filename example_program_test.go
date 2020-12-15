// +build linux

package ebpf_test

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// This demonstrates how to attach an eBPF program to a tracepoint.
// The program will be attached to the sys_enter_open syscall and print out the integer
// 123 everytime the sycall is used.
func Example_tracepoint() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		panic(fmt.Errorf("could not create event map: %v\n", err))
	}
	defer events.Close()

	rd, err := perf.NewReader(events, os.Getpagesize())
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
				if perf.IsClosed(err) {
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
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: ins,
	})
	if err != nil {
		panic(fmt.Errorf("could not create new ebpf program: %v", err))
	}
	defer prog.Close()

	tp, err := link.AttachTracepoint(link.TracepointOptions{
		Name:    "syscalls/sys_enter_open",
		Program: prog,
	})
	if err != nil {
		panic(fmt.Errorf("can't attach tracepoint: %s", err))
	}
	defer tp.Close()

	<-ctx.Done()
}
