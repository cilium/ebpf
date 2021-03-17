package link

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

// Getting the terminology right is usually the hardest part. For posterity and
// for staying sane during implementation:
//
// - trace event: Representation of a kernel runtime hook. Filesystem entries
//   under <tracefs>/events. Can be tracepoints (static), kprobes or uprobes.
//   Can be instantiated into perf events (see below).
// - tracepoint: A predetermined hook point in the kernel. Exposed as trace
//   events in (sub)directories under <tracefs>/events. Cannot be closed or
//   removed, they are static.
// - k(ret)probe: Ephemeral trace events based on entry or exit points of
//   exported kernel symbols. kprobe-based (tracefs) trace events can be
//   created system-wide by writing to the <tracefs>/kprobe_events file, or
//   they can be scoped to the current process by creating PMU perf events.
// - perf event: An object instantiated based on an existing trace event or
//   kernel symbol. Referred to by fd in userspace.
//   Exactly one eBPF program can be attached to a perf event. Multiple perf
//   events can be created from a single trace event. Closing a perf event
//   stops any further invocations of the attached eBPF program.

var (
	tracefsPath = "/sys/kernel/debug/tracing"

	// Trace event groups, names and kernel symbols must adhere to this set
	// of characters. Non-empty, first character must not be a number, all
	// characters must be alphanumeric or underscore.
	rgxTraceEvent = regexp.MustCompile("^[a-zA-Z_][0-9a-zA-Z_]*$")
)

const (
	perfAllThreads = -1
)

// A TraceEvent represents a trace event in the Linux kernel.
type TraceEvent struct {
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
}

// Close releases the resources associated with the TraceEvent.
func (te *TraceEvent) Close() error {
	if te.group == "" || te.name == "" {
		return errors.New("cannot close an empty trace event")
	}

	switch t := te.progType; t {
	case ebpf.Kprobe:
		return te.closeKprobe()
	case ebpf.TracePoint:
		return nil
	default:
		return fmt.Errorf("unknown program type for trace event: %s", t)
	}
}

// Attach opens a new perf event for the TraceEvent and attaches the given
// program to it.
func (te *TraceEvent) Attach(program *ebpf.Program) (Link, error) {
	if program == nil {
		return nil, errors.New("cannot attach a nil program")
	}
	if t := program.Type(); t != te.progType {
		return nil, fmt.Errorf("invalid program type (expected %s): %s", te.progType, t)
	}
	if program.FD() < 0 {
		return nil, fmt.Errorf("invalid program: %w", internal.ErrClosedFd)
	}

	var ifd *internal.FD

	switch {
	case te.pmuID != 0:
		// Open a PMU perf event based on a sysfs PMU type.
		fd, err := te.perfEventOpenPMU()
		if err != nil {
			return nil, fmt.Errorf("open PMU trace event: %w", err)
		}
		ifd = fd

	case te.tracefsID != 0:
		// Open a perf event based on a tracefs trace event ID.
		fd, err := te.perfEventOpenTraceFS()
		if err != nil {
			return nil, fmt.Errorf("open tracefs perf event: %w", err)
		}
		ifd = fd

	default:
		return nil, errors.New("need a PMU type or tracefs ID")
	}

	kfd, err := ifd.Value()
	if err != nil {
		return nil, fmt.Errorf("getting perf event fd: %w", err)
	}

	// Assign the eBPF program to the perf event.
	err = unix.IoctlSetInt(int(kfd), unix.PERF_EVENT_IOC_SET_BPF, program.FD())
	if err != nil {
		return nil, fmt.Errorf("setting perf event bpf program: %w", err)
	}

	// PERF_EVENT_IOC_ENABLE and _DISABLE ignore their given values.
	if err := unix.IoctlSetInt(int(kfd), unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		ifd.Close()
		return nil, fmt.Errorf("enable perf event: %s", err)
	}

	return &perfEvent{
		fd:       ifd,
		progType: te.progType,
	}, nil
}

func (te *TraceEvent) perfEventOpenPMU() (*internal.FD, error) {
	if te.pmuID == 0 {
		return nil, errors.New("missing PMU type")
	}

	// Create a pointer to a NUL-terminated string for the kernel.
	symbol, err := unsafeStringPtr(te.name)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("trace event '%s' not found: %w", te.name, err)
	}
	if err != nil {
		return nil, err
	}

	// Ensure the string pointer is not collected before PerfEventOpen returns.
	runtime.KeepAlive(symbol)

	return internal.NewFD(uint32(fd)), nil
}

func (te *TraceEvent) perfEventOpenTraceFS() (*internal.FD, error) {
	if te.tracefsID == 0 {
		return nil, errors.New("missing trace event tracefs ID")
	}

	// Must be a tracepoint event regardless of the attach type of the program.
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      te.tracefsID,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(&attr, perfAllThreads, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, err
	}

	return internal.NewFD(uint32(fd)), nil
}

func (te *TraceEvent) closeKprobe() error {
	// Only kprobe trace events can be closed.
	if te.tracefsID != 0 {
		return closeTraceFSKprobeEvent(te.group, te.name)
	}
	return nil
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
// group and name must be alphanumeric or underscore, as required by the kernel.
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

	data, err := ioutil.ReadFile(p)
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
}

func (ev *perfEvent) isLink() {}

func (ev *perfEvent) Pin(string) error {
	return fmt.Errorf("pin perf event: %w", ErrNotSupported)
}

// Since 4.15 (e87c6bc3852b "bpf: permit multiple bpf attachments for a single perf event"),
// calling PERF_EVENT_IOC_SET_BPF appends the given program to a prog_array
// owned by the perf event, which means multiple programs can be attached
// simultaneously.
//
// Before 4.15, calling PERF_EVENT_IOC_SET_BPF more than once on a perf event
// returns EEXIST.
//
// Detaching a program from a perf event is currently not possible, so a
// program replacement mechanism cannot be implemented for perf events.
func (ev *perfEvent) Update(prog *ebpf.Program) error {
	return fmt.Errorf("can't replace BPF program in perf event: %w", ErrNotSupported)
}

func (ev *perfEvent) Close() error {
	pfd, err := ev.fd.Value()
	if err != nil {
		return fmt.Errorf("getting perf event fd: %w", err)
	}

	err = unix.IoctlSetInt(int(pfd), unix.PERF_EVENT_IOC_DISABLE, 0)
	if err != nil {
		return fmt.Errorf("disabling perf event: %w", err)
	}

	return ev.fd.Close()
}
