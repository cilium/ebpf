// This program demonstrates how to attach an eBPF program to a tracepoint.
// The program is attached to the syscall/sys_enter_openat tracepoint and
// prints out the integer 123 every time the syscall is entered.
package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Metadata for the eBPF program used in this example.
var progSpec = &ebpf.ProgramSpec{
	Name:    "my_trace_prog", // non-unique name, will appear in `bpftool prog list` while attached
	Type:    ebpf.TracePoint, // only TracePoint programs can be attached to trace events created by link.Tracepoint()
	License: "GPL",           // license must be GPL for calling kernel helpers like perf_event_output
}

func main() {

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Create a perf event array for the kernel to write perf records to.
	// These records will be read by userspace below.
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "my_perf_array",
	})
	if err != nil {
		log.Fatalf("creating perf event array: %s", err)
	}
	defer events.Close()

	// Open a perf reader from userspace into the perf event array
	// created earlier.
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper
		rd.Close()
	}()

	// Minimal program that writes the static value '123' to the perf ring on
	// each event. Note that this program refers to the file descriptor of
	// the perf event array created above, which needs to be created prior to the
	// program being verified by and inserted into the kernel.
	progSpec.Instructions = asm.Instructions{
		// store the integer 123 at FP[-8]
		asm.Mov.Imm(asm.R2, 123),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.Word),

		// load registers with arguments for call of FnPerfEventOutput
		asm.LoadMapPtr(asm.R2, events.FD()), // file descriptor of the perf event array
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -8),
		asm.Mov.Imm(asm.R5, 4),

		// call FnPerfEventOutput, an eBPF kernel helper
		asm.FnPerfEventOutput.Call(),

		// set exit code to 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Instantiate and insert the program into the kernel.
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}
	defer prog.Close()

	// Open a trace event based on a pre-existing kernel hook (tracepoint).
	// Each time a userspace program uses the 'openat()' syscall, the eBPF
	// program specified above will be executed and a '123' value will appear
	// in the perf ring.
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		log.Println("Record:", record)
	}
}
