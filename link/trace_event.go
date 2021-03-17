package link

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"golang.org/x/sys/unix"
)

// Getting the terminology right is usually the hardest part. For posterity and
// for staying sane during implementation:
//
// - trace event: Entry under <tracefs>/events. Can be tracepoints or kprobes.
//   Cannot be closed, as they are static objects. Can be instantiated into
//   perf events (see below).
// - tracepoint: A predetermined hook point in the kernel. Exposed as trace
//   events in (sub)directories under <tracefs>/events. Cannot be instantiated,
//   closed or removed, it is static.
// - k(ret)probe: Ephemeral trace events based on entry or exit points of
//   arbitrary exported kernel symbols. kprobe-based (tracefs) trace events can
//   be created system-wide by writing to the <tracefs>/kprobe_events file, or
//   they can be scoped to the current process by creating PMU perf events.
// - perf event: An object instantiated based on an existing trace event or
//   kernel symbol. Referred to by fd in userspace.
//   Exactly one eBPF program can be attached to a perf event. Multiple perf
//   events can be created from a single trace event. Closing a perf event
//   stops any further invocations of the attached eBPF program.

var (
	tracefsPath = "/sys/kernel/debug/tracing"

	// Trace event groups and names must adhere to this set of characters.
	rgxTraceEvent = regexp.MustCompile("^[a-zA-Z0-9_-]+$")
)

const (
	perfAllThreads = -1
)

// A traceEvent represents a trace event in the Linux kernel.
type traceEvent struct {
	// Group and name of the tracepoint/kprobe/uprobe.
	group string
	name  string

	// PMU event ID read from sysfs. Valid IDs are non-zero.
	pmuID uint64
	// ID of the trace event read from tracefs. Valid IDs are non-zero.
	tracefsID uint64

	// True for kretprobes/uretprobes.
	ret bool

	// Type of program this trace event will accept to be attached.
	progType ebpf.ProgramType

	// finalizer is called during Close() and is only set if the trace event
	// has associated resources that need to be cleaned up.
	finalizer func() error
}

// Close releases the resources associated with the TraceEvent.
func (te *traceEvent) Close() error {
	if te.finalizer == nil {
		return nil
	}
	return te.finalizer()
}

// Attach opens a new perf event for the TraceEvent and attaches the given
// program to it.
func (te *traceEvent) Attach(program *ebpf.Program) (Link, error) {
	if program == nil {
		return nil, errors.New("cannot attach a nil program")
	}

	var pfd int

	switch {
	case te.pmuID != 0:
		// Open a PMU perf event based on a sysfs PMU type.
		fd, err := te.perfEventOpenPMU()
		if err != nil {
			return nil, fmt.Errorf("open PMU trace event: %w", err)
		}
		pfd = fd

	case te.tracefsID != 0:
		// Open a perf event based on a tracefs trace event ID.
		fd, err := te.perfEventOpenTraceFS()
		if err != nil {
			return nil, fmt.Errorf("open tracefs perf event: %w", err)
		}
		pfd = fd

	default:
		return nil, errors.New("need a PMU type or tracefs ID")
	}

	// PERF_EVENT_IOC_ENABLE and _DISABLE ignore their given values.
	if err := unix.IoctlSetInt(pfd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(pfd)
		return nil, fmt.Errorf("enable perf event: %s", err)
	}

	pe := &perfEvent{
		fd:       internal.NewFD(uint32(pfd)),
		progType: te.progType,
	}

	if err := pe.Update(program); err != nil {
		pe.Close()
		return nil, fmt.Errorf("attaching perf event: %w", err)
	}

	return pe, nil
}

func (te *traceEvent) perfEventOpenPMU() (int, error) {
	if te.pmuID == 0 {
		return 0, errors.New("missing PMU type")
	}

	// Create a pointer to a NUL-terminated string for the kernel.
	symbol, err := unsafeStringPtr(te.name)
	if err != nil {
		return 0, err
	}

	// TODO: Parse the position of the bit from /sys/bus/event_source/devices/%s/format/retprobe.
	config := 0
	if te.ret {
		config = 1
	}

	attr := unix.PerfEventAttr{
		Type:   uint32(te.pmuID),
		Ext1:   uint64(uintptr(symbol)), // Kernel symbol to trace
		Config: uint64(config),          // perf_kprobe PMU treats config as flags
	}

	fd, err := unix.PerfEventOpen(&attr, perfAllThreads, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	// Presence of the traced kernel object is not checked until here.
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("trace event '%s' not found: %w", te.name, err)
	}
	if err != nil {
		return 0, err
	}

	// Ensure the string pointer is not collected before PerfEventOpen returns.
	runtime.KeepAlive(symbol)

	return fd, nil
}

func (te *traceEvent) perfEventOpenTraceFS() (int, error) {
	if te.tracefsID == 0 {
		return 0, errors.New("missing trace event tracefs ID")
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      te.tracefsID,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(&attr, perfAllThreads, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// unsafeStringPtr returns an unsafe.Pointer to a NUL-terminated copy of str.
func unsafeStringPtr(str string) (unsafe.Pointer, error) {
	p, err := unix.BytePtrFromString(str)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(p), nil
}

// getTraceEventID reads a trace event's ID from tracefs given its group and name.
// group and name must be alphanumeric (with _-), as required by the kernel.
func getTraceEventID(group, name string) (uint64, error) {
	tid, err := uint64FromFile(tracefsPath, "events", group, name, "id")
	if errors.Is(err, ErrNotSupported) {
		return 0, fmt.Errorf("trace event %s/%s: %w", group, name, ErrNotSupported)
	}
	if err != nil {
		return 0, fmt.Errorf("reading trace event ID of %s/%s: %w", group, name, err)
	}

	return tid, nil
}

// getPMUEventType reads a Performance Monitoring Unit's type (numeric identifier)
// from /sys/bus/event_source/devices/<pmu>/type.
func getPMUEventType(pmu string) (uint64, error) {
	et, err := uint64FromFile("/sys/bus/event_source/devices", pmu, "type")
	if errors.Is(err, ErrNotSupported) {
		return 0, fmt.Errorf("pmu type %s: %w", pmu, ErrNotSupported)
	}
	if err != nil {
		return 0, fmt.Errorf("reading pmu type %s: %w", pmu, err)
	}

	return et, nil
}

// uint64FromFile reads a uint64 from a file. All elements of path are sanitized
// and joined onto base. Returns error if base no longer prefixes the path after
// joining all components.
func uint64FromFile(base string, path ...string) (uint64, error) {

	// Resolve leaf path separately for error feedback. Makes the join onto
	// base more readable (can't mix with variadic args).
	l := filepath.Join(path...)

	p := filepath.Join(base, l)
	if !strings.HasPrefix(p, base) {
		return 0, fmt.Errorf("path '%s' attempts to escape base path '%s': %w", l, base, ErrInvalidInput)
	}

	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		// Only echo leaf path, the base path can be prepended at the call site
		// if more verbosity is required.
		return 0, fmt.Errorf("symbol %s: %w", l, ErrNotSupported)
	}
	if err != nil {
		return 0, fmt.Errorf("reading file %s: %w", p, err)
	}

	et := bytes.TrimSpace(data)
	return strconv.ParseUint(string(et), 10, 64)
}

// A perfEvent represents a perf event kernel object. Exactly one eBPF program
// can be attached to it. It is created based on a tracefs trace event or a
// Performance Monitoring Unit (PMU).
type perfEvent struct {
	fd       *internal.FD
	progType ebpf.ProgramType
	prog     *ebpf.Program
}

func (ev *perfEvent) isLink() {}

func (ev *perfEvent) Pin(string) error {
	return fmt.Errorf("pin perf event: %w", ErrNotSupported)
}

func (ev *perfEvent) Update(prog *ebpf.Program) error {
	if t := prog.Type(); t != ev.progType {
		return fmt.Errorf("invalid program type (expected %s): %s", ev.progType, t)
	}
	if prog.FD() < 0 {
		return fmt.Errorf("invalid program: %w", internal.ErrClosedFd)
	}

	// Return if the given prog is already attached.
	if ev.prog == prog {
		return nil
	}

	pfd, err := ev.fd.Value()
	if err != nil {
		return fmt.Errorf("getting perf event fd: %w", err)
	}

	err = unix.IoctlSetInt(int(pfd), unix.PERF_EVENT_IOC_SET_BPF, prog.FD())
	if err != nil {
		return fmt.Errorf("setting perf event bpf program: %w", err)
	}

	// Store a reference to the attached program.
	ev.prog = prog

	return nil
}

func (ev *perfEvent) Close() error {
	return ev.fd.Close()
}
