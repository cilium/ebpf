package testutils

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/rlimit"
)

func init() {
	// Don't adjust rlimit in a user namespace, we won't have permission to do so.
	if _, ok := os.LookupEnv(setupUserNS); ok {
		return
	}

	// Increase the memlock for all tests unconditionally. It's a great source of
	// weird bugs, since different distros have different default limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: Failed to adjust rlimit, tests may fail")
	}
}
