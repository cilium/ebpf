package internal

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/internal/unix"
)

func RemoveMemlockRlimit() error {
	var oldLimit unix.Rlimit
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &oldLimit); err != nil {
		return fmt.Errorf("retrieve RLIMIT_MEMLOCK: %s", err)
	}

	// Reduce the limit to zero. This is always allowed.
	newLimit := unix.Rlimit{Cur: 0, Max: oldLimit.Max}
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &newLimit, &oldLimit); err != nil {
		return fmt.Errorf("lower RLIMIT_MEMLOCK: %s", err)
	}

	attr := BPFMapCreateAttr{
		MapType:    2, /* Array */
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}

	fd, err := BPFMapCreate(&attr)
	if !errors.Is(err, unix.EPERM) {
		if err != nil {
			// This shouldn't happen really.
			return fmt.Errorf("determine whether RLIMIT_MEMLOCK is used: %s", err)
		}

		// The kernel uses memcg, all good. Restore the old limits.
		if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &oldLimit, nil); err != nil {
			return fmt.Errorf("restore old RLIMIT_MEMLOCK: %s", err)
		}

		fd.Close()
		return nil
	}

	// This kernel accounts against RLIMIT_MEMLOCK, bump it to the max.
	newLimit = unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}

	// pid 0 affects the current process. Requires CAP_SYS_RESOURCE.
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &newLimit, nil); err != nil {
		return fmt.Errorf("failed to set memlock rlimit: %w", err)
	}

	return nil
}
