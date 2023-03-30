package lite

import (
	"errors"
	"fmt"
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
	tp, err := pmuKprobe(args)
	if err == nil {
		return nil
	}
	if err != nil && !errors.Is(err, internal.ErrNotSupported) {
		return fmt.Errorf("creating perf_kprobe PMU (arch-specific fallback for %q): %w", symbol, err)
	}

	// Use tracefs if kprobe PMU is missing.
	args.symbol = symbol
	tp, err = tracefsKprobe(args)
	if err != nil {
		return nil, fmt.Errorf("creating tracefs event (arch-specific fallback for %q): %w", symbol, err)
	}

	return tp, nil
}

// pmuKprobe opens a perf event based on the kprobe PMU.
// Returns os.ErrNotExist if the given symbol does not exist in the kernel.
func pmuKprobe(args probeArgs) error {
	// Getting the PMU type will fail if the kernel doesn't support
	// the perf_[k,u]probe PMU.
	et, err := readUint64FromFileOnce("%d\n", "/sys/bus/event_source/devices", typ.String(), "type")
	if err != nil {
		return err
	}

	var config uint64
	if args.ret {
		bit, err := readUint64FromFileOnce("config:%d\n", "/sys/bus/event_source/devices", typ.String(), "/format/retprobe")
		if err != nil {
			return nil, err
		}
		config |= 1 << bit
	}

	var (
		attr unix.PerfEventAttr
		sp   unsafe.Pointer
	)
	// Create a pointer to a NUL-terminated string for the kernel.
	sp, err = unsafeStringPtr(args.symbol)
	if err != nil {
		return nil, err
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
