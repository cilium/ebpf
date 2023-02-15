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
	sys.OnLeakFD(func(fs *runtime.Frames) {
		fmt.Fprintln(os.Stderr, "leaked fd created at:")
		fmt.Fprintln(os.Stderr, formatFrames(fs))
		os.Exit(1)
	})

	ret := m.Run()

	sys.OnLeakFD(nil)

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
