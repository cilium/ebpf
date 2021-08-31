package ebpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// RemoveMemlockRlimit removes the limit on the amount of memory
// the process can lock into RAM.
func RemoveMemlockRlimit() error {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		return fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}
	return nil
}
