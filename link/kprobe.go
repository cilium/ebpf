package link

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

var (
	kprobeEventsPath = filepath.Join(tracefsPath, "kprobe_events")
)

// Kprobe returns a TraceEvent that fires when the given kernel symbol starts
// executing. See /proc/kallsyms for available symbols. For example, printk():
//
//	Kprobe("printk")
//
// As of kernel 4.15, the presence of the given symbol is only checked when
// attaching a program. One TraceEvent can be re-used to attach an arbitrary
// number of programs.
func Kprobe(symbol string) (*TraceEvent, error) {
	return kprobe(symbol, false)
}

// Kretprobe returns a TraceEvent that fires right before the given kernel
// symbol exits, with the function stack left intact.
// See /proc/kallsyms for available symbols. For example, printk():
//
//	Kretprobe("printk")
//
// As of kernel 4.15, the presence of the given symbol is only checked when
// attaching a program. One TraceEvent can be re-used to attach an arbitrary
// number of programs.
func Kretprobe(symbol string) (*TraceEvent, error) {
	return kprobe(symbol, true)
}

// kprobe returns a TraceEvent backed by a k(ret)probe
// of the given kernel symbol.
func kprobe(symbol string, ret bool) (*TraceEvent, error) {
	if symbol == "" {
		return nil, errors.New("symbol name cannot be empty")
	}
	if !rgxTraceEvent.MatchString(symbol) {
		return nil, fmt.Errorf("symbol must be alphanumeric or underscore: %s", symbol)
	}

	// Use kprobe PMU if the kernel has it available.
	tp, err := pmuKprobe(symbol, ret)
	if err == nil {
		return tp, nil
	}
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("creating perf_kprobe PMU: %w", err)
	}

	// Use tracefs if kprobe PMU is missing.
	tp, err = tracefsKprobe(symbol, ret)
	if err != nil {
		return nil, fmt.Errorf("creating trace event '%s' in tracefs: %w", symbol, err)
	}

	return tp, nil
}

// pmuKprobe returns a TraceEvent to be created using PMU (sysfs).
func pmuKprobe(symbol string, ret bool) (*TraceEvent, error) {
	et, err := getPMUEventType("kprobe")
	if err != nil {
		return nil, err
	}
	return &TraceEvent{
		pmuID:    et,
		name:     symbol,
		ret:      ret,
		progType: ebpf.Kprobe,
	}, nil
}

// tracefsKprobe returns a TraceEvent created by writing an entry to
// <tracefs>/kprobe_events. On Close(), the entry is removed.
// A new group identifier is generated on every call to ensure uniqueness.
func tracefsKprobe(symbol string, ret bool) (*TraceEvent, error) {

	// Generate a random string for each trace event we attempt to create.
	// This value is used as the 'group' token in tracefs to allow creating
	// multiple kprobe trace events with the same name.
	group := mustRandomGroup("ebpf")

	// Before attempting to create a trace event through tracefs,
	// check if an event with the same group and name already exists.
	// Kernels 4.x and earlier don't return os.ErrExist on writing a duplicate
	// entry, so we need to rely on reads for detecting uniqueness.
	_, err := getTraceEventID(group, symbol)
	if err == nil {
		return nil, fmt.Errorf("trace event already exists: %s/%s", group, symbol)
	}
	// The read is expected to fail with ErrNotSupported due to a non-existing event.
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("checking trace event %s/%s: %w", group, symbol, err)
	}

	// Create the kprobe trace event using tracefs.
	if err := createTraceFSKprobeEvent(group, symbol, ret); err != nil {
		return nil, fmt.Errorf("creating kprobe event on tracefs: %w", err)
	}

	// Get the newly-created trace event's id.
	tid, err := getTraceEventID(group, symbol)
	if err != nil {
		return nil, fmt.Errorf("getting trace event id: %w", err)
	}

	return &TraceEvent{
		group:     group,
		name:      symbol,
		ret:       ret,
		tracefsID: tid,
		progType:  ebpf.Kprobe, // kernel only allows attaching kprobe programs to kprobe events
	}, nil
}

// createTraceFSKprobeEvent creates a new ephemeral trace event by writing to
// <tracefs>/kprobe_events. Returns ErrNotSupported if symbol is not a valid
// kernel symbol, or if it is not traceable with kprobes.
func createTraceFSKprobeEvent(group, symbol string, ret bool) error {
	// Open the kprobe_events file in tracefs.
	f, err := os.OpenFile(kprobeEventsPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("error opening kprobe_events: %w", err)
	}
	defer f.Close()

	// The kprobe_events syntax is as follows (see Documentation/trace/kprobetrace.txt):
	// p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS] : Set a probe
	// r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS] : Set a return probe
	// -:[GRP/]EVENT                                        : Clear a probe
	//
	// Some examples:
	// r:ebpf_1234/r_my_kretprobe nf_conntrack_destroy
	// p:ebpf_5678/p_my_kprobe __x64_sys_execve
	//
	// Leaving the kretprobe's MAXACTIVE set to 0 (or absent) will make the
	// kernel default to NR_CPUS. This is desired in most all eBPF cases since
	// subsampling or rate limiting logic can be more accurately implemented in
	// the eBPF program itself. See Documentation/kprobes.txt for more details.
	pe := fmt.Sprintf("%s:%s/%s %s", kprobePrefix(ret), group, symbol, symbol)
	_, err = f.WriteString(pe)
	// Writing to <tracefs>/kprobe_events will return ENOENT when the tracee
	// kernel symbol does not exist (yet) in the kernel.
	if os.IsNotExist(err) {
		return fmt.Errorf("kernel symbol %s not found: %w", symbol, ErrNotSupported)
	}
	if err != nil {
		return fmt.Errorf("writing '%s' to kprobe_events: %w", pe, err)
	}

	return nil
}

// closeTraceFSKprobeEvent removes the kprobe with the given group, symbol and kind
// from <tracefs>/kprobe_events.
func closeTraceFSKprobeEvent(group, symbol string) error {
	f, err := os.OpenFile(kprobeEventsPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("error opening kprobe_events: %w", err)
	}
	defer f.Close()

	// See kprobe_events syntax above. Kprobe type does not need to be specified
	// for removals.
	pe := fmt.Sprintf("-:%s/%s", group, symbol)
	if _, err = f.WriteString(pe); err != nil {
		return fmt.Errorf("writing '%s' to kprobe_events: %w", pe, err)
	}

	return nil
}

// mustRandomGroup generates a pseudorandom string for use as a tracefs group name.
// Panics when the output string would exceed 63 characters (kernel limitation),
// when rand.Read() fails or when prefix contains characters not allowed by
// rgxTraceEvent.
func mustRandomGroup(prefix string) string {
	if !rgxTraceEvent.MatchString(prefix) {
		panic(fmt.Sprintf("group name prefix must be alphanumeric or underscore: %s", prefix))
	}

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	group := fmt.Sprintf("%s_%x", prefix, b)
	if len(group) > 63 {
		panic(fmt.Sprintf("group name cannot be longer than 63 characters: %s", group))
	}

	return group
}

func kprobePrefix(ret bool) string {
	if ret {
		return "r"
	}
	return "p"
}
