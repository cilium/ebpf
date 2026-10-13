package testmain

import (
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils/fdtrace"
)

type testingM interface {
	Run() int
}

// Run m with various debug aids enabled.
//
// The function calls [os.Exit] and does not return.
func Run(m testingM) {
	const traceLogFlag = "trace-log"

	var ts *traceSession
	if platform.IsWindows {
		traceLog := flag.Bool(traceLogFlag, false, "Output a trace of eBPF runtime activity")
		flag.Parse()

		if *traceLog {
			var err error
			ts, err = newTraceSession()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Disabling trace logging:", err)
			}
		}
	}
	defer ts.Close()

	fdtrace.Enable()
	ret := m.Run()

	if fdtrace.CheckLeaks() {
		ret = 99
	}

	if err := ts.Dump(os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error while dumping trace log:", err)
		ret = 99
	}

	if platform.IsWindows && ret != 0 && ts == nil {
		fmt.Fprintf(os.Stderr, "Consider enabling trace logging with -%s\n", traceLogFlag)
	}

	os.Exit(ret)
}
