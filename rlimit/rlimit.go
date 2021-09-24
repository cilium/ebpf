// Package rlimit allows raising RLIMIT_MEMLOCK if necessary for the use of BPF.
package rlimit

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	unsupportedMemcgAccounting = &internal.UnsupportedFeatureError{
		MinimumVersion: internal.Version{5, 11, 0},
		Name:           "memcg-based accounting for BPF memory",
	}
	haveMemcgAccounting error
)

func init() {
	// We have to run this feature test at init, since it relies on changing
	// RLIMIT_MEMLOCK. Doing so is not safe in a concurrent program. Instead,
	// we rely on the initialization order guaranteed by the Go runtime to
	// execute the test in a safe environment:
	//    the invocation of init functions—happens in a single goroutine,
	//    sequentially, one package at a time.
	// This is also the reason why RemoveMemlock is in its own package:
	// we only want to run the initializer if RemoveMemlock is called
	// from somewhere.
	haveMemcgAccounting = detectMemcgAccounting()
}

func detectMemcgAccounting() error {
	var oldLimit unix.Rlimit
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &oldLimit); err != nil {
		return fmt.Errorf("retrieve RLIMIT_MEMLOCK: %s", err)
	}

	// Reduce the limit to zero. This is always allowed.
	zeroLimit := unix.Rlimit{Cur: 0, Max: oldLimit.Max}
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &zeroLimit, &oldLimit); err != nil {
		return fmt.Errorf("lower RLIMIT_MEMLOCK: %s", err)
	}

	attr := internal.BPFMapCreateAttr{
		MapName:    internal.NewBPFObjName("memcg_account"),
		MapType:    2, /* Array */
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}

	fd, mapErr := internal.BPFMapCreate(&attr)
	// Restore the old limits regardless of what happens.
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &oldLimit, nil); err != nil {
		return fmt.Errorf("restore old RLIMIT_MEMLOCK: %s", err)
	}
	if mapErr == nil {
		fd.Close()
		return nil
	}

	if !errors.Is(mapErr, unix.EPERM) {
		// This shouldn't happen really.
		return fmt.Errorf("determine whether RLIMIT_MEMLOCK is used: %s", mapErr)
	}

	return unsupportedMemcgAccounting
}

var (
	prlimitLock    sync.Mutex
	memlockRemoved bool
)

// RemoveMemlock removes the limit on the amount of memory the current
// process can lock into RAM, if necessary.
//
// This is not required to load eBPF resources on kernel versions 5.11+
// due to the introduction of cgroup-based memory accounting. On such kernels
// the function is a no-op.
//
// Since the function may change global per-process limits it should be invoked
// at program start up, in main() or init().
//
// This function exists as a convenience and should only be used when
// permanently raising RLIMIT_MEMLOCK to infinite is appropriate. Consider
// invoking prlimit(2) directly if that is not the case.
//
// Requires CAP_SYS_RESOURCE on kernels < 5.11.
func RemoveMemlock() error {
	if haveMemcgAccounting == nil {
		return nil
	}

	if !errors.Is(haveMemcgAccounting, unsupportedMemcgAccounting) {
		return haveMemcgAccounting
	}

	prlimitLock.Lock()
	defer prlimitLock.Unlock()

	if memlockRemoved {
		return nil
	}

	// pid 0 affects the current process. Requires CAP_SYS_RESOURCE.
	newLimit := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &newLimit, nil); err != nil {
		return fmt.Errorf("failed to set memlock rlimit: %w", err)
	}

	memlockRemoved = true
	return nil
}
