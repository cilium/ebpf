package fdtrace

import (
	"bytes"
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
		fmt.Fprintln(os.Stderr, formatFrames(fs))
		leak = true
	})

	ret := m.Run()

	sys.OnLeakFD(nil)

	if leak {
		ret = 99
	}

	os.Exit(ret)
}

func formatFrames(fs *runtime.Frames) string {
	var b bytes.Buffer
	for {
		f, more := fs.Next()
		b.WriteString(fmt.Sprintf("\t%s+%#x\n\t\t%s:%d\n", f.Function, f.PC-f.Entry, f.File, f.Line))
		if !more {
			break
		}
	}
	return b.String()
}
