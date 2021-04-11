package link

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	symbolsCache = internal.NewSymbolsCache()
}

var (
	uprobeEventsPath = filepath.Join(tracefsPath, "uprobe_events")

	// reUprobeSymbol is used to strip invalid characters from the uprobe symbol
	// as they are not allowed to be used as the EVENT token in tracefs.
	reUprobeSymbol = regexp.MustCompile("[^a-zA-Z0-9]+")

	// TODO(matt): discuss if a cache is needed and if the current implementation
	// is correct.
	symbolsCache *internal.SymbolsCache
)

// Uprobe attaches the given eBPF program to a perf event that fires when the
// given symbol starts executing in the given binary.
// For example, /bin/bash::readline():
//
//	Uprobe("/bin/bash", "readline", prog)
//
// The resulting Link must be Closed during program shutdown to avoid leaking
// system resources.
//
// Since the implementation of Uprobe is similar to the implementation of Kprobe,
// some functions in this file are not documented thorougly.
// For a more complete documentation, refer to the Kprobe implementation.
func Uprobe(path, symbol string, prog *ebpf.Program) (Link, error) {
	u, err := uprobe(path, symbol, prog, false)
	if err != nil {
		return nil, err
	}

	err = u.attach(prog)
	if err != nil {
		u.Close()
		return nil, err
	}

	return u, nil
}

// Uretprobe attaches the given eBPF program to a perf event that fires right
// before the given symbol exits.
//
// The resulting Link must be Closed during program shutdown to avoid leaking
// system resources.
func Uretprobe(path, symbol string, prog *ebpf.Program) (Link, error) {
	u, err := uprobe(path, symbol, prog, true)
	if err != nil {
		return nil, err
	}

	err = u.attach(prog)
	if err != nil {
		u.Close()
		return nil, err
	}

	return u, nil
}

// uprobe opens a perf event for the given binary/symbol and attaches prog to it.
// If ret is true, create a uretprobe.
func uprobe(path, symbol string, prog *ebpf.Program, ret bool) (*perfEvent, error) {
	if path == "" {
		return nil, fmt.Errorf("binary path cannot be empty: %w", errInvalidInput)
	}
	if symbol == "" {
		return nil, fmt.Errorf("symbol name cannot be empty: %w", errInvalidInput)
	}
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if !rgxTraceEvent.MatchString(symbol) {
		return nil, fmt.Errorf("symbol '%s' must be alphanumeric or underscore: %w", symbol, errInvalidInput)
	}
	if prog.Type() != ebpf.Kprobe {
		return nil, fmt.Errorf("eBPF program type %s is not a Kprobe: %w", prog.Type(), errInvalidInput)
	}

	// Get elf.Symbol from the symbols cache.
	// If an elf.Symbol for the given (path,symbol) is not present,
	// the cache will be filled with all the symbols found in the ELF file.
	s, err := symbolsCache.Get(path, symbol)
	if err != nil {
		return nil, fmt.Errorf("read ELF file '%s' for symbol '%s': %w", path, symbol, err)
	}

	// Use uprobe PMU if the kernel has it available.
	tp, err := pmuUprobe(s, path, symbol, ret)
	if err == nil {
		return tp, nil
	}
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("creating perf_uprobe PMU: %w", err)
	}

	// Use tracefs if uprobe PMU is missing.
	tp, err = tracefsUprobe(s, path, symbol, ret)
	if err != nil {
		return nil, fmt.Errorf("creating trace event '%s::%s' in tracefs: %w", path, symbol, err)
	}

	return tp, nil
}

// pmuUprobe opens a perf event based on a Performance Monitoring Unit.
// Requires at least the kernel version 4.17
// (33ea4b24277b06dbc55d7f5772a46f029600255e "perf/core: Implement the 'perf_uprobe' PMU").
func pmuUprobe(s *elf.Symbol, path, symbol string, ret bool) (*perfEvent, error) {
	et, err := getPMUEventType("uprobe")
	if err != nil {
		return nil, err
	}

	sp, err := unsafeStringPtr(path)
	if err != nil {
		return nil, err
	}

	attr := unix.PerfEventAttr{
		Type: uint32(et),               // PMU event type read from sysfs
		Ext1: uint64(uintptr(sp)),      // Uprobe path
		Ext2: uint64(uintptr(s.Value)), // Uprobe offset
	}
	if ret {
		retprobeBit, err := determineRetprobeBit("uprobe")
		if err != nil {
			return nil, fmt.Errorf("determine retprobe bit: %w", err)
		}
		attr.Config |= 1 << retprobeBit
	}

	fd, err := unix.PerfEventOpen(&attr, perfAllThreads, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("opening perf event: %w", err)
	}

	// Ensure the string pointer is not collected before PerfEventOpen returns.
	runtime.KeepAlive(sp)

	// Kernel has perf_uprobe PMU available, initialize perf event.
	return &perfEvent{
		fd:       internal.NewFD(uint32(fd)),
		pmuID:    et,
		name:     symbol,
		ret:      ret,
		progType: ebpf.Kprobe,
		isUprobe: true,
	}, nil
}

// tracefsUprobe creates a trace event by writing an entry to <tracefs>/uprobe_events.
// A new trace event group name is generated on every call to support creating
// multiple trace events for the same symbol.
func tracefsUprobe(s *elf.Symbol, path, symbol string, ret bool) (*perfEvent, error) {
	group, err := randomGroup("ebpf")
	if err != nil {
		return nil, fmt.Errorf("randomizing group name: %w", err)
	}

	// Uprobe' symbols can contain invalid characters for the tracefs api.
	sanitizedSymbol := uprobeSanitizedSymbol(symbol)
	pathOffset := uprobePathOffset(path, s)

	// Before attempting to create a trace event through tracefs,
	// check if an event with the same group and name already exists.
	_, err = getTraceEventID(group, sanitizedSymbol)
	if err == nil {
		return nil, fmt.Errorf("trace event already exists: %s/%s", group, sanitizedSymbol)
	}
	// The read is expected to fail with ErrNotSupported due to a non-existing event.
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("checking trace event %s/%s: %w", group, sanitizedSymbol, err)
	}

	// Create the uprobe trace event using tracefs.
	if err := createTraceFSUprobeEvent(group, sanitizedSymbol, pathOffset, ret); err != nil {
		return nil, fmt.Errorf("creating uprobe event on tracefs: %w", err)
	}

	// Get the newly-created trace event's id.
	tid, err := getTraceEventID(group, sanitizedSymbol)
	if err != nil {
		return nil, fmt.Errorf("getting trace event id: %w", err)
	}

	// Uprobes are ephemeral tracepoints and share the same perf event type.
	fd, err := openTracepointPerfEvent(tid)
	if err != nil {
		return nil, err
	}

	return &perfEvent{
		fd:        fd,
		group:     group,
		name:      sanitizedSymbol,
		ret:       ret,
		tracefsID: tid,
		progType:  ebpf.Kprobe,
		isUprobe:  true,
	}, nil
}

// createTraceFSUprobeEvent creates a new ephemeral trace event by writing to
// <tracefs>/uprobe_events.
func createTraceFSUprobeEvent(group, sanitizedSymbol, pathOffset string, ret bool) error {
	// Open the uprobe_events file in tracefs.
	f, err := os.OpenFile(uprobeEventsPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("error opening uprobe_events: %w", err)
	}
	defer f.Close()

	// The uprobe_events syntax is as follows:
	// p[:[GRP/]EVENT] PATH:OFFSET [FETCHARGS] : Set a uprobe
	// r[:[GRP/]EVENT] PATH:OFFSET [FETCHARGS] : Set a return uprobe (uretprobe)
	// -:[GRP/]EVENT                           : Clear uprobe or uretprobe event
	//
	// Some examples:
	// r:ebpf_1234/readline readline:0x12345
	// p:ebpf_5678/main_mySymbol main.mySymbol:0x12345
	//
	// See Documentation/trace/uprobetracer.txt for more details.
	pe := fmt.Sprintf("%s:%s/%s %s", probePrefix(ret), group, sanitizedSymbol, pathOffset)
	_, err = f.WriteString(pe)
	if err != nil {
		return fmt.Errorf("writing '%s' to uprobe_events: %w", pe, err)
	}
	return nil
}

// closeTraceFSUprobeEvent removes the uprobe with the given group, symbol and kind
// from <tracefs>/uprobe_events.
func closeTraceFSUprobeEvent(group, sanitizedSymbol string) error {
	f, err := os.OpenFile(uprobeEventsPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("error opening uprobe_events: %w", err)
	}
	defer f.Close()

	pe := fmt.Sprintf("-:%s/%s", group, sanitizedSymbol)
	if _, err = f.WriteString(pe); err != nil {
		return fmt.Errorf("writing '%s' to uprobe_events: %w", pe, err)
	}
	return nil
}

// uprobeSanitizedSymbol replaces every non valid characted for the tracefs api with an underscore.
func uprobeSanitizedSymbol(symbol string) string {
	return reUprobeSymbol.ReplaceAllString(symbol, "_")
}

// uprobePathOffset creates the PATH:OFFSET token for the tracefs api.
func uprobePathOffset(path string, s *elf.Symbol) string {
	return fmt.Sprintf("%s:%#x", path, s.Value)
}
