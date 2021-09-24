package internal

import (
	"fmt"

	"github.com/cilium/ebpf/internal/unix"
)

func RemoveMemlockRlimit() (func() error, error) {
	var oldLimit unix.Rlimit
	newLimit := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}

	// pid 0 affects the current process.
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &newLimit, &oldLimit); err != nil {
		return nil, fmt.Errorf("failed to set memlock rlimit: %w", err)
	}

	return func() error {
		if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &oldLimit, nil); err != nil {
			return fmt.Errorf("failed to revert memlock rlimit: %w", err)
		}
		return nil
	}, nil
}
