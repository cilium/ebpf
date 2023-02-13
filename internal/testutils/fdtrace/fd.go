package fdtrace

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/sys"
)

func TestMain(m *testing.M) {
	sys.Finalize = exiter

	ret := m.Run()

	if sys.FDs.Len() > 0 {
		fmt.Fprintln(os.Stderr, "leaked file descriptors:")
		fmt.Fprintln(os.Stderr, sys.FDs.String())
		os.Exit(1)
	}

	sys.Finalize = nil

	os.Exit(ret)
}

// exiter prints t and exits the application with return code 1.
func exiter(t sys.FDTrace) {
	fmt.Fprintln(os.Stderr, "closed by gc:", t)
	os.Exit(1)
}
