package lite

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

type probeArgs struct {
	symbol, group string
	pid           int
}

func KprobeCheckLite(symbol string, pid int) error {
	fd, err := tryAttach(symbol, pid)
	if err != nil {
		return err
	}
	_ = fd.Close()
	return nil
}

func tryAttach(symbol string, pid int) (*sys.FD, error) {
	args := probeArgs{
		symbol: symbol,
		pid:    pid,
	}

	// Use tracefs if kprobe PMU is missing.
	return tracefsKprobe(args)
}

// tracefsKprobe creates a Kprobe tracefs entry.
func tracefsKprobe(args probeArgs) (*sys.FD, error) {
	groupPrefix := "ebpf"
	if args.group != "" {
		groupPrefix = args.group
	}

	// Generate a random string for each trace event we attempt to create.
	// This value is used as the 'group' token in tracefs to allow creating
	// multiple kprobe trace events with the same name.
	group, err := internal.RandomTraceFSGroup(groupPrefix)
	if err != nil {
		return nil, err
	}
	args.group = group

	// Create the [k,u]probe trace event using tracefs.
	tid, err := createTraceFSKProbeEvent(args)
	if err != nil {
		return nil, err
	}

	// Kprobes are ephemeral tracepoints and share the same perf event type.
	fd, err := internal.OpenTracepointPerfEvent(tid, args.pid)

	// Make sure we clean up the created tracefs event when we return error.
	// If a livepatch handler is already active on the symbol, the write to
	// tracefs will succeed, a trace event will show up, but creating the
	// perf event will fail with EBUSY.
	_ = closeTraceFSKProbeEvent(args.group, args.symbol)
	return fd, err
}

func createTraceFSKProbeEvent(args probeArgs) (uint64, error) {
	// Before attempting to create a trace event through tracefs,
	// check if an event with the same group and name already exists.
	// Kernels 4.x and earlier don't return os.ErrExist on writing a duplicate
	// entry, so we need to rely on reads for detecting uniqueness.
	_, err := internal.GetTraceEventID(args.group, args.symbol)
	if err == nil {
		return 0, fmt.Errorf("trace event %s/%s: %w", args.group, args.symbol, os.ErrExist)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("checking trace event %s/%s: %w", args.group, args.symbol, err)
	}

	// Open the kprobe_events file in tracefs.
	f, err := kprobeEventsFile()
	if err != nil {
		return 0, err
	}
	defer f.Close()

	token := args.symbol
	pe := fmt.Sprintf("%s:%s/%s %s", internal.ProbePrefix(false, 0), args.group, internal.SanitizeSymbol(args.symbol), token)
	_, err = f.WriteString(pe)
	if err != nil {
		return 0, err
	}

	// Get the newly-created trace event's id.
	tid, err := internal.GetTraceEventID(args.group, args.symbol)
	if err != nil {
		return 0, fmt.Errorf("get trace event id: %w", err)
	}

	return tid, nil
}

func closeTraceFSKProbeEvent(group, symbol string) error {
	pe := fmt.Sprintf("%s/%s", group, internal.SanitizeSymbol(symbol))
	return removeTraceFSKProbeEvent(pe)
}

func removeTraceFSKProbeEvent(pe string) error {
	f, err := kprobeEventsFile()
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString("-:" + pe); err != nil {
		return fmt.Errorf("remove event %q from %s: %w", pe, f.Name(), err)
	}

	return nil
}

func kprobeEventsFile() (*os.File, error) {
	path, err := internal.SanitizeTracefsPath("kprobe_events")
	if err != nil {
		return nil, err
	}

	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
}
