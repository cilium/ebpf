package ebpf

import (
	"syscall"
)

const (
	_SYS_PERF_EVENT_OPEN = syscall.SYS_PERF_EVENT_OPEN
	_EBADFD              = syscall.EBADFD
)
