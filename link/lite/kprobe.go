package lite

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

type probeArgs struct {
	symbol, group, path          string
	offset, refCtrOffset, cookie uint64
	pid                          int
	ret                          bool
}

func KprobeLite(symbol string, args probeArgs) error {
	// Use kprobe PMU if the kernel has it available.
	err := pmuKprobe(args)
	if err == nil {
		return nil
	}
	if err != nil && !errors.Is(err, internal.ErrNotSupported) {
		return err
	}

	// Use tracefs if kprobe PMU is missing.
	args.symbol = symbol
	if err := tracefsKprobe(args); err != nil {
		return err
	}

	return nil
}

// pmuKprobe opens a perf event based on the kprobe PMU.
// Returns os.ErrNotExist if the given symbol does not exist in the kernel.
func pmuKprobe(args probeArgs) error {
	// Getting the PMU type will fail if the kernel doesn't support
	// the perf_[k,u]probe PMU.
	et, err := internal.ReadUint64FromFileOnce("%d\n", "/sys/bus/event_source/devices/kprobe/type")
	if err != nil {
		return err
	}

	var config uint64
	if args.ret {
		bit, err := internal.ReadUint64FromFileOnce("config:%d\n", "/sys/bus/event_source/devices/kprobe/format/retprobe")
		if err != nil {
			return err
		}
		config |= 1 << bit
	}

	var (
		attr unix.PerfEventAttr
		sp   unsafe.Pointer
	)
	// Create a pointer to a NUL-terminated string for the kernel.
	sp, err = internal.UnsafeStringPtr(args.symbol)
	if err != nil {
		return err
	}

	attr = unix.PerfEventAttr{
		// The minimum size required for PMU kprobes is PERF_ATTR_SIZE_VER1,
		// since it added the config2 (Ext2) field. Use Ext2 as probe_offset.
		Size:   unix.PERF_ATTR_SIZE_VER1,
		Type:   uint32(et),          // PMU event type read from sysfs
		Ext1:   uint64(uintptr(sp)), // Kernel symbol to trace
		Ext2:   args.offset,         // Kernel symbol offset
		Config: config,              // Retprobe flag
	}

	if _, err = unix.PerfEventOpen(&attr, args.pid, 0, -1, unix.PERF_FLAG_FD_CLOEXEC); err != nil {
		return err
	}

	// Ensure the string pointer is not collected before PerfEventOpen returns.
	runtime.KeepAlive(sp)

	return nil
}

// tracefsKprobe creates a Kprobe tracefs entry.
func tracefsKprobe(args probeArgs) error {
	groupPrefix := "ebpf"
	if args.group != "" {
		groupPrefix = args.group
	}

	// Generate a random string for each trace event we attempt to create.
	// This value is used as the 'group' token in tracefs to allow creating
	// multiple kprobe trace events with the same name.
	group, err := internal.RandomTraceFSGroup(groupPrefix)
	if err != nil {
		return err
	}
	args.group = group

	// Create the [k,u]probe trace event using tracefs.
	tid, err := createTraceFSKProbeEvent(args)
	if err != nil {
		return err
	}

	// Kprobes are ephemeral tracepoints and share the same perf event type.
	fd, err := openTracepointPerfEvent(tid, args.pid)
	if err != nil {
		// Make sure we clean up the created tracefs event when we return error.
		// If a livepatch handler is already active on the symbol, the write to
		// tracefs will succeed, a trace event will show up, but creating the
		// perf event will fail with EBUSY.
		_ = closeTraceFSProbeEvent(typ, args.group, args.symbol)
		return err
	}

	return nil
}

func createTraceFSKProbeEvent(args probeArgs) (uint64, error) {
	// Before attempting to create a trace event through tracefs,
	// check if an event with the same group and name already exists.
	// Kernels 4.x and earlier don't return os.ErrExist on writing a duplicate
	// entry, so we need to rely on reads for detecting uniqueness.
	_, err := getTraceEventID(args.group, args.symbol)
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

	token := kprobeToken(args)
	pe := fmt.Sprintf("%s:%s/%s %s", probePrefix(args.ret, 0), args.group, sanitizeSymbol(args.symbol), token)
	_, err = f.WriteString(pe)
	if err != nil {
		return 0, err
	}

	// Get the newly-created trace event's id.
	tid, err := getTraceEventID(args.group, args.symbol)
	if err != nil {
		return 0, fmt.Errorf("get trace event id: %w", err)
	}

	return tid, nil
}

func closeTraceFSKProbeEvent(group, symbol string) error {
	pe := fmt.Sprintf("%s/%s", group, sanitizeSymbol(symbol))
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
