package fdtrace

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal/sys"
)

// TestMain runs m with sys.FD leak tracing enabled.
func TestMain(m *testing.M) {
	// fn can either be invoked asynchronously by the gc or during disabling of
	// the leak tracer below. Don't terminate the program immediately, instead
	// capture a boolean that will be used to set the exit code. This avoids races
	// and gives all events the chance to be written to stderr.
	var leak bool
	sys.OnLeakFD(func(fs *runtime.Frames) {
		fmt.Fprintln(os.Stderr, "leaked fd created at:")
		fmt.Fprintln(os.Stderr, sys.FormatFrames(fs))
		leak = true
	})

	ret := m.Run()

	sys.OnLeakFD(nil)

	if leak {
		ret = 99
	}

	os.Exit(ret)
}
