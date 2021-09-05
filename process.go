package ebpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// RemoveMemlockRlimit removes the limit on the amount of memory
// the process can lock into RAM. Returns a function that restores
// the limit to its previous value. This is not required to load
// eBPF resources on kernel versions 5.11+ due to the introduction
// of cgroup-bases memory accounting.
func RemoveMemlockRlimit() (func() error, error) {
	oldLimit := new(unix.Rlimit)
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, oldLimit); err != nil {
		return nil, fmt.Errorf("failed to get memlock rlimit: %w", err)
	}

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		return nil, fmt.Errorf("failed to set memlock rlimit: %w", err)
	}

	return func() error {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, oldLimit); err != nil {
			return fmt.Errorf("failed to reset memlock rlimit: %w", err)
		}
		return nil
	}, nil
}
