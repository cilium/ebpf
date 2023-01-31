package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

// PeriodicOptions defines additional parameters that will be used
// when loading periodic samplers.
type PeriodicOptions struct {
	// Arbitrary value that can be fetched from an eBPF program
	// via `bpf_get_attach_cookie()`.
	//
	// Needs kernel 5.15+.
	Cookie uint64
}

// Periodic attaches the given eBPF program to a periodic perf event on given
// cpu and given frequency.
//
// This is mainly useful when doing sample-based tracing or monitoring.
//
// Losing the reference to the resulting Link (tp) will close the Periodic event
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
func Periodic(frequency uint64, cpu int, prog *ebpf.Program, opts *PeriodicOptions) (Link, error) {
	possibleCPUs, err := internal.PossibleCPUs()
	if err != nil {
		return nil, err
	}

	if frequency == 0 {
		return nil, fmt.Errorf("frequency can not be 0: %w", errInvalidInput)
	}
	if cpu < 0 || cpu > possibleCPUs {
		return nil, fmt.Errorf("cpu must be greater to 0 and lower than %d: %w", possibleCPUs, errInvalidInput)
	}
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if prog.Type() != ebpf.PerfEvent {
		return nil, fmt.Errorf("eBPF program type %s is not a PerfEvent: %w", prog.Type(), errInvalidInput)
	}

	fd, err := openPeriodicPerfEvent(frequency, cpu)
	if err != nil {
		return nil, err
	}

	var cookie uint64
	if opts != nil {
		cookie = opts.Cookie
	}

	pe := &perfEvent{
		typ:    periodicEvent,
		cookie: cookie,
		fd:     fd,
	}

	lnk, err := attachPerfEvent(pe, prog)
	if err != nil {
		pe.Close()
		return nil, err
	}

	return lnk, nil
}

// PeriodicAllCpus attaches the given eBPF program to a periodic event fired at
// given frequency on each cpu.
//
// See Periodic above for more information.
func PeriodicAllCpus(frequency uint64, prog *ebpf.Program, opts *PeriodicOptions) ([]Link, error) {
	possibleCPUs, err := internal.PossibleCPUs()
	if err != nil {
		return nil, err
	}

	links := make([]Link, possibleCPUs)

	for i := 0; i < len(links); i++ {
		links[i], err = Periodic(frequency, i, prog, opts)
		if err != nil {
			// Links are automatically closed "some" time after the last reference is lost
			return nil, fmt.Errorf("failed to link periodic prog on CPU %d: %w", i, err)
		}
	}

	return links, nil
}
