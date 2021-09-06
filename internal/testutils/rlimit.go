package testutils

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	// Increase the memlock for all tests unconditionally. It's a great source of
	// weird bugs, since different distros have different default limits.
	_, err := unix.RemoveMemlockRlimit()
	if err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: Failed to adjust rlimit, tests may fail")
	}
}
