package link

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Tracepoint returns a trace event for the given tracepoint group and name.
// See /sys/kernel/debug/tracing/events to find available tracepoints. The
// top-level directory is group, the event's subdirectory is name. Example:
//
//	Tracepoint("syscalls", "sys_enter_fork")
//
// Note that attaching eBPF programs to syscalls (sys_enter_*/sys_exit_*) is
// only possible as of kernel 4.14 (commit cf5f5ce).
//
// Multiple calls with the same group and name are unnecessary. TracePoints
// can be re-used to Attach() an arbitrary amount of eBPF programs. Closing a
// Tracepoint will not disconnect attached perf events.
func Tracepoint(group, name string) (*TraceEvent, error) {
	if group == "" || name == "" {
		return nil, errors.New("group and name cannot be empty")
	}
	if !rgxTraceEvent.MatchString(group) || !rgxTraceEvent.MatchString(name) {
		return nil, fmt.Errorf("group and name must be alphanumeric or underscore: %s/%s", group, name)
	}

	tid, err := getTraceEventID(group, name)
	if err != nil {
		return nil, err
	}

	return &TraceEvent{
		tracefsID: tid,
		group:     group,
		name:      name,
		progType:  ebpf.TracePoint,
	}, nil
}
