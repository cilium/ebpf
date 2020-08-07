// +build linux

package ebpf_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/perf"

	"golang.org/x/sys/unix"
)

// getTracepointID returns the system specific ID for the tracepoint sys_enter_open.
func getTracepointID() (uint64, error) {
	data, err := ioutil.ReadFile("/sys/kernel/debug/tracing/events/syscalls/sys_enter_open/id")
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for 'sys_enter_open': %v", err)
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}

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
		Name:         "sys_enter_open",
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: ins,
	})
	if err != nil {
		panic(fmt.Errorf("could not create new ebpf program: %v", err))
	}
	defer prog.Close()

	tid, err := getTracepointID()
	if err != nil {
		panic(fmt.Errorf("could not get tracepoint id: %v", err))
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      tid,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		panic(fmt.Errorf("unable to open perf events: %v", err))
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_ENABLE, 0); errno != 0 {
		panic(fmt.Errorf("unable to enable perf events: %v", err))
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(prog.FD())); errno != 0 {
		panic(fmt.Errorf("unable to attach bpf program to perf events: %v", err))
	}

	<-ctx.Done()

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_DISABLE, 0); errno != 0 {
		panic(fmt.Errorf("unable to disable perf events: %v", err))
	}
}
