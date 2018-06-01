//+build !linux

package ebpf

import (
	"syscall"
)

// These syscall numbers are not available on non-Linux platforms.
// Stub them out to allow code completion to work at least.
const (
	_SYS_PERF_EVENT_OPEN = 0xdeadbeef
	_EBADFD              = syscall.Errno(0xdeadbeef)
)
