package link

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cilium/ebpf"
)

var (
	uprobeEventsPath = filepath.Join(tracefsPath, "uprobe_events")

	// rgxUprobeSymbol is used to strip invalid characters from the uprobe symbol
	// as they are not allowed to be used as the EVENT token in tracefs.
	rgxUprobeSymbol = regexp.MustCompile("[^a-zA-Z0-9]+")

	uprobeRetprobeBit = struct {
		once  sync.Once
		value uint64
		err   error
	}{}
)

// Uprobe attaches the given eBPF program to a perf event that fires when the
// given symbol starts executing in the given Executable.
// For example, /bin/bash::readline():
//
//	Executable("/bin/bash").Uprobe("readline", prog)
//
// The resulting Link must be Closed during program shutdown to avoid leaking
// system resources.
func (ex *executable) Uprobe(symbol string, prog *ebpf.Program) (Link, error) {
	u, err := ex.uprobe(symbol, prog, false)
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
func (ex *executable) Uretprobe(symbol string, prog *ebpf.Program) (Link, error) {
	u, err := ex.uprobe(symbol, prog, true)
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
func (ex *executable) uprobe(symbol string, prog *ebpf.Program, ret bool) (*perfEvent, error) {
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if prog.Type() != ebpf.Kprobe {
		return nil, fmt.Errorf("eBPF program type %s is not Kprobe: %w", prog.Type(), errInvalidInput)
	}

	sym, err := ex.symbolByName(symbol)
	if err != nil {
		return nil, fmt.Errorf("symbol '%s' not found in '%s': %w", symbol, ex.path, err)
	}

	// Use uprobe PMU if the kernel has it available.
	tp, err := pmuProbe(uprobeType, sym.Name, ex.path, sym.Value, ret)
	if err == nil {
		return tp, nil
	}
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("creating perf_uprobe PMU: %w", err)
	}

	// Use tracefs if uprobe PMU is missing.
	tp, err = tracefsProbe(uprobeType, uprobeSanitizedSymbol(sym.Name), ex.path, sym.Value, ret)
	if err != nil {
		return nil, fmt.Errorf("creating trace event '%s:%s' in tracefs: %w", ex.path, symbol, err)
	}

	return tp, nil
}

// uprobeSanitizedSymbol replaces every non valid characted for the tracefs api with an underscore.
func uprobeSanitizedSymbol(symbol string) string {
	return rgxUprobeSymbol.ReplaceAllString(symbol, "_")
}

// uprobePathOffset creates the PATH:OFFSET token for the tracefs api.
func uprobePathOffset(path string, offset uint64) string {
	return fmt.Sprintf("%s:%#x", path, offset)
}

func uretprobeBit() (uint64, error) {
	uprobeRetprobeBit.once.Do(func() {
		uprobeRetprobeBit.value, uprobeRetprobeBit.err = determineRetprobeBit(uprobeType)
	})
	return uprobeRetprobeBit.value, uprobeRetprobeBit.err
}
