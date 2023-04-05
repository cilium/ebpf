package link

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/tracefs"
	"github.com/cilium/ebpf/internal/unix"
)

// KprobeOptions defines additional parameters that will be used
// when loading Kprobes.
type KprobeOptions struct {
	// Arbitrary value that can be fetched from an eBPF program
	// via `bpf_get_attach_cookie()`.
	//
	// Needs kernel 5.15+.
	Cookie uint64
	// Offset of the kprobe relative to the traced symbol.
	// Can be used to insert kprobes at arbitrary offsets in kernel functions,
	// e.g. in places where functions have been inlined.
	Offset uint64
	// Increase the maximum number of concurrent invocations of a kretprobe.
	// Required when tracing some long running functions in the kernel.
	//
	// Deprecated: this setting forces the use of an outdated kernel API and is not portable
	// across kernel versions.
	RetprobeMaxActive int
	// Prefix used for the event name if the kprobe must be attached using tracefs.
	// The group name will be formatted as `<prefix>_<randomstr>`.
	// The default empty string is equivalent to "ebpf" as the prefix.
	TraceFSPrefix string
}

func PerfEventTypeFromProbeType(pt tracefs.ProbeType, ret bool) perfEventType {
	if pt == tracefs.KprobeType {
		if ret {
			return kretprobeEvent
		}
		return kprobeEvent
	}
	if ret {
		return uretprobeEvent
	}
	return uprobeEvent
}

// Kprobe attaches the given eBPF program to a perf event that fires when the
// given kernel symbol starts executing. See /proc/kallsyms for available
// symbols. For example, printk():
//
//	kp, err := Kprobe("printk", prog, nil)
//
// Losing the reference to the resulting Link (kp) will close the Kprobe
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
//
// If attaching to symbol fails, automatically retries with the running
// platform's syscall prefix (e.g. __x64_) to support attaching to syscalls
// in a portable fashion.
func Kprobe(symbol string, prog *ebpf.Program, opts *KprobeOptions) (Link, error) {
	k, err := kprobe(symbol, prog, opts, false)
	if err != nil {
		return nil, err
	}

	lnk, err := attachPerfEvent(k, prog)
	if err != nil {
		k.Close()
		return nil, err
	}

	return lnk, nil
}

// Kretprobe attaches the given eBPF program to a perf event that fires right
// before the given kernel symbol exits, with the function stack left intact.
// See /proc/kallsyms for available symbols. For example, printk():
//
//	kp, err := Kretprobe("printk", prog, nil)
//
// Losing the reference to the resulting Link (kp) will close the Kretprobe
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
//
// If attaching to symbol fails, automatically retries with the running
// platform's syscall prefix (e.g. __x64_) to support attaching to syscalls
// in a portable fashion.
//
// On kernels 5.10 and earlier, setting a kretprobe on a nonexistent symbol
// incorrectly returns unix.EINVAL instead of os.ErrNotExist.
func Kretprobe(symbol string, prog *ebpf.Program, opts *KprobeOptions) (Link, error) {
	k, err := kprobe(symbol, prog, opts, true)
	if err != nil {
		return nil, err
	}

	lnk, err := attachPerfEvent(k, prog)
	if err != nil {
		k.Close()
		return nil, err
	}

	return lnk, nil
}

// isValidKprobeSymbol implements the equivalent of a regex match
// against "^[a-zA-Z_][0-9a-zA-Z_.]*$".
func isValidKprobeSymbol(s string) bool {
	if len(s) < 1 {
		return false
	}

	for i, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '_':
		case i > 0 && c >= '0' && c <= '9':

		// Allow `.` in symbol name. GCC-compiled kernel may change symbol name
		// to have a `.isra.$n` suffix, like `udp_send_skb.isra.52`.
		// See: https://gcc.gnu.org/gcc-10/changes.html
		case i > 0 && c == '.':

		default:
			return false
		}
	}

	return true
}

// kprobe opens a perf event on the given symbol and attaches prog to it.
// If ret is true, create a kretprobe.
func kprobe(symbol string, prog *ebpf.Program, opts *KprobeOptions, ret bool) (*perfEvent, error) {
	if symbol == "" {
		return nil, fmt.Errorf("symbol name cannot be empty: %w", errInvalidInput)
	}
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if !isValidKprobeSymbol(symbol) {
		return nil, fmt.Errorf("symbol '%s' must be a valid symbol in /proc/kallsyms: %w", symbol, errInvalidInput)
	}
	if prog.Type() != ebpf.Kprobe {
		return nil, fmt.Errorf("eBPF program type %s is not a Kprobe: %w", prog.Type(), errInvalidInput)
	}

	args := tracefs.ProbeArgs{
		Pid:    perfAllThreads,
		Symbol: symbol,
		Ret:    ret,
	}

	if opts != nil {
		args.RetprobeMaxActive = opts.RetprobeMaxActive
		args.Cookie = opts.Cookie
		args.Offset = opts.Offset
		args.Group = opts.TraceFSPrefix
	}

	// Use kprobe PMU if the kernel has it available.
	tp, err := pmuKprobe(args)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.EINVAL) {
		if prefixedSymbol, ok := internal.PlatformPrefix(symbol); ok {
			args.Symbol = prefixedSymbol
			tp, err = pmuKprobe(args)
		}
	}
	if err == nil {
		return tp, nil
	}
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("creating perf_kprobe PMU (arch-specific fallback for %q): %w", symbol, err)
	}

	// Use tracefs if kprobe PMU is missing.
	args.Symbol = symbol
	tp, err = tracefsKprobe(args)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.EINVAL) {
		if prefixedSymbol, ok := internal.PlatformPrefix(symbol); ok {
			args.Symbol = prefixedSymbol
			tp, err = tracefsKprobe(args)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("creating tracefs event (arch-specific fallback for %q): %w", symbol, err)
	}

	return tp, nil
}

// pmuKprobe opens a perf event based on the kprobe PMU.
// Returns os.ErrNotExist if the given symbol does not exist in the kernel.
func pmuKprobe(args tracefs.ProbeArgs) (*perfEvent, error) {
	return pmuProbe(tracefs.KprobeType, args)
}

// pmuProbe opens a perf event based on a Performance Monitoring Unit.
//
// Requires at least a 4.17 kernel.
// e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU"
// 33ea4b24277b "perf/core: Implement the 'perf_uprobe' PMU"
//
// Returns ErrNotSupported if the kernel doesn't support perf_[k,u]probe PMU
func pmuProbe(typ tracefs.ProbeType, args tracefs.ProbeArgs) (*perfEvent, error) {
	// Getting the PMU type will fail if the kernel doesn't support
	// the perf_[k,u]probe PMU.
	et, err := internal.ReadUint64FromFileOnce("%d\n", "/sys/bus/event_source/devices", typ.String(), "type")
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", typ, ErrNotSupported)
	}
	if err != nil {
		return nil, err
	}

	// Use tracefs if we want to set kretprobe's retprobeMaxActive.
	if args.RetprobeMaxActive != 0 {
		return nil, fmt.Errorf("pmu probe: non-zero retprobeMaxActive: %w", ErrNotSupported)
	}

	var config uint64
	if args.Ret {
		bit, err := internal.ReadUint64FromFileOnce("config:%d\n", "/sys/bus/event_source/devices", typ.String(), "/format/retprobe")
		if err != nil {
			return nil, err
		}
		config |= 1 << bit
	}

	var (
		attr  unix.PerfEventAttr
		sp    unsafe.Pointer
		token string
	)
	switch typ {
	case tracefs.KprobeType:
		// Create a pointer to a NUL-terminated string for the kernel.
		sp, err = internal.UnsafeStringPtr(args.Symbol)
		if err != nil {
			return nil, err
		}

		token = tracefs.KprobeToken(args)

		attr = unix.PerfEventAttr{
			// The minimum size required for PMU kprobes is PERF_ATTR_SIZE_VER1,
			// since it added the config2 (Ext2) field. Use Ext2 as probe_offset.
			Size:   unix.PERF_ATTR_SIZE_VER1,
			Type:   uint32(et),          // PMU event type read from sysfs
			Ext1:   uint64(uintptr(sp)), // Kernel symbol to trace
			Ext2:   args.Offset,         // Kernel symbol offset
			Config: config,              // Retprobe flag
		}
	case tracefs.UprobeType:
		sp, err = internal.UnsafeStringPtr(args.Path)
		if err != nil {
			return nil, err
		}

		if args.RefCtrOffset != 0 {
			config |= args.RefCtrOffset << uprobeRefCtrOffsetShift
		}

		token = tracefs.UprobeToken(args)

		attr = unix.PerfEventAttr{
			// The minimum size required for PMU uprobes is PERF_ATTR_SIZE_VER1,
			// since it added the config2 (Ext2) field. The Size field controls the
			// size of the internal buffer the kernel allocates for reading the
			// perf_event_attr argument from userspace.
			Size:   unix.PERF_ATTR_SIZE_VER1,
			Type:   uint32(et),          // PMU event type read from sysfs
			Ext1:   uint64(uintptr(sp)), // Uprobe path
			Ext2:   args.Offset,         // Uprobe offset
			Config: config,              // RefCtrOffset, Retprobe flag
		}
	}

	rawFd, err := unix.PerfEventOpen(&attr, args.Pid, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)

	// On some old kernels, kprobe PMU doesn't allow `.` in symbol names and
	// return -EINVAL. Return ErrNotSupported to allow falling back to tracefs.
	// https://github.com/torvalds/linux/blob/94710cac0ef4/kernel/trace/trace_kprobe.c#L340-L343
	if errors.Is(err, unix.EINVAL) && strings.Contains(args.Symbol, ".") {
		return nil, fmt.Errorf("token %s: older kernels don't accept dots: %w", token, ErrNotSupported)
	}
	// Since commit 97c753e62e6c, ENOENT is correctly returned instead of EINVAL
	// when trying to create a retprobe for a missing symbol.
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("token %s: not found: %w", token, err)
	}
	// Since commit ab105a4fb894, EILSEQ is returned when a kprobe sym+offset is resolved
	// to an invalid insn boundary. The exact conditions that trigger this error are
	// arch specific however.
	if errors.Is(err, unix.EILSEQ) {
		return nil, fmt.Errorf("token %s: bad insn boundary: %w", token, os.ErrNotExist)
	}
	// Since at least commit cb9a19fe4aa51, ENOTSUPP is returned
	// when attempting to set a uprobe on a trap instruction.
	if errors.Is(err, sys.ENOTSUPP) {
		return nil, fmt.Errorf("token %s: failed setting uprobe on offset %#x (possible trap insn): %w", token, args.Offset, err)
	}

	if err != nil {
		return nil, fmt.Errorf("token %s: opening perf event: %w", token, err)
	}

	// Ensure the string pointer is not collected before PerfEventOpen returns.
	runtime.KeepAlive(sp)

	fd, err := sys.NewFD(rawFd)
	if err != nil {
		return nil, err
	}

	// Kernel has perf_[k,u]probe PMU available, initialize perf event.
	return &perfEvent{
		typ:    PerfEventTypeFromProbeType(typ, args.Ret),
		name:   args.Symbol,
		pmuID:  et,
		cookie: args.Cookie,
		fd:     fd,
	}, nil
}

// tracefsKprobe creates a Kprobe tracefs entry.
func tracefsKprobe(args tracefs.ProbeArgs) (*perfEvent, error) {
	return tracefsProbe(tracefs.KprobeType, args)
}

// tracefsProbe creates a trace event by writing an entry to <tracefs>/[k,u]probe_events.
// A new trace event group name is generated on every call to support creating
// multiple trace events for the same kernel or userspace symbol.
// Path and offset are only set in the case of uprobe(s) and are used to set
// the executable/library path on the filesystem and the offset where the probe is inserted.
// A perf event is then opened on the newly-created trace event and returned to the caller.
func tracefsProbe(typ tracefs.ProbeType, args tracefs.ProbeArgs) (*perfEvent, error) {
	groupPrefix := "ebpf"
	if args.Group != "" {
		groupPrefix = args.Group
	}

	// Generate a random string for each trace event we attempt to create.
	// This value is used as the 'group' token in tracefs to allow creating
	// multiple kprobe trace events with the same name.
	group, err := tracefs.RandomGroup(groupPrefix)
	if err != nil {
		return nil, fmt.Errorf("randomizing group name: %w", err)
	}
	args.Group = group

	// Create the [k,u]probe trace event using tracefs.
	tid, err := createTraceFSProbeEvent(typ, args)
	if err != nil {
		return nil, fmt.Errorf("creating probe entry on tracefs: %w", err)
	}

	// Kprobes are ephemeral tracepoints and share the same perf event type.
	fd, err := tracefs.OpenTracepointPerfEvent(tid, args.Pid)
	if err != nil {
		// Make sure we clean up the created tracefs event when we return error.
		// If a livepatch handler is already active on the symbol, the write to
		// tracefs will succeed, a trace event will show up, but creating the
		// perf event will fail with EBUSY.
		_ = closeTraceFSProbeEvent(typ, args.Group, args.Symbol)
		return nil, err
	}

	return &perfEvent{
		typ:       PerfEventTypeFromProbeType(typ, args.Ret),
		group:     group,
		name:      args.Symbol,
		tracefsID: tid,
		cookie:    args.Cookie,
		fd:        fd,
	}, nil
}

var errInvalidMaxActive = errors.New("can only set maxactive on kretprobes")

// createTraceFSProbeEvent creates a new ephemeral trace event.
//
// Returns os.ErrNotExist if symbol is not a valid
// kernel symbol, or if it is not traceable with kprobes. Returns os.ErrExist
// if a probe with the same group and symbol already exists. Returns an error if
// args.RetprobeMaxActive is used on non kprobe types. Returns ErrNotSupported if
// the kernel is too old to support kretprobe maxactive.
func createTraceFSProbeEvent(typ tracefs.ProbeType, args tracefs.ProbeArgs) (uint64, error) {
	// Before attempting to create a trace event through tracefs,
	// check if an event with the same group and name already exists.
	// Kernels 4.x and earlier don't return os.ErrExist on writing a duplicate
	// entry, so we need to rely on reads for detecting uniqueness.
	_, err := tracefs.GetTraceEventID(args.Group, args.Symbol)
	if err == nil {
		return 0, fmt.Errorf("trace event %s/%s: %w", args.Group, args.Symbol, os.ErrExist)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("checking trace event %s/%s: %w", args.Group, args.Symbol, err)
	}

	// Open the kprobe_events file in tracefs.
	f, err := typ.EventsFile()
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var pe, token string
	switch typ {
	case tracefs.KprobeType:
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
		// kernel default to NR_CPUS. This is desired in most eBPF cases since
		// subsampling or rate limiting logic can be more accurately implemented in
		// the eBPF program itself.
		// See Documentation/kprobes.txt for more details.
		if args.RetprobeMaxActive != 0 && !args.Ret {
			return 0, errInvalidMaxActive
		}
		token = tracefs.KprobeToken(args)
		pe = fmt.Sprintf("%s:%s/%s %s", tracefs.ProbePrefix(args.Ret, args.RetprobeMaxActive), args.Group, tracefs.SanitizeSymbol(args.Symbol), token)
	case tracefs.UprobeType:
		// The uprobe_events syntax is as follows:
		// p[:[GRP/]EVENT] PATH:OFFSET [FETCHARGS] : Set a probe
		// r[:[GRP/]EVENT] PATH:OFFSET [FETCHARGS] : Set a return probe
		// -:[GRP/]EVENT                           : Clear a probe
		//
		// Some examples:
		// r:ebpf_1234/readline /bin/bash:0x12345
		// p:ebpf_5678/main_mySymbol /bin/mybin:0x12345(0x123)
		//
		// See Documentation/trace/uprobetracer.txt for more details.
		if args.RetprobeMaxActive != 0 {
			return 0, errInvalidMaxActive
		}
		token = tracefs.UprobeToken(args)
		pe = fmt.Sprintf("%s:%s/%s %s", tracefs.ProbePrefix(args.Ret, 0), args.Group, args.Symbol, token)
	}
	_, err = f.WriteString(pe)

	// Since commit 97c753e62e6c, ENOENT is correctly returned instead of EINVAL
	// when trying to create a retprobe for a missing symbol.
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("token %s: not found: %w", token, err)
	}
	// Since commit ab105a4fb894, EILSEQ is returned when a kprobe sym+offset is resolved
	// to an invalid insn boundary. The exact conditions that trigger this error are
	// arch specific however.
	if errors.Is(err, syscall.EILSEQ) {
		return 0, fmt.Errorf("token %s: bad insn boundary: %w", token, os.ErrNotExist)
	}
	// ERANGE is returned when the `SYM[+offs]` token is too big and cannot
	// be resolved.
	if errors.Is(err, syscall.ERANGE) {
		return 0, fmt.Errorf("token %s: offset too big: %w", token, os.ErrNotExist)
	}

	if err != nil {
		return 0, fmt.Errorf("token %s: writing '%s': %w", token, pe, err)
	}

	// Get the newly-created trace event's id.
	tid, err := tracefs.GetTraceEventID(args.Group, args.Symbol)
	if args.RetprobeMaxActive != 0 && errors.Is(err, os.ErrNotExist) {
		// Kernels < 4.12 don't support maxactive and therefore auto generate
		// group and event names from the symbol and offset. The symbol is used
		// without any sanitization.
		// See https://elixir.bootlin.com/linux/v4.10/source/kernel/trace/trace_kprobe.c#L712
		event := fmt.Sprintf("kprobes/r_%s_%d", args.Symbol, args.Offset)
		if err := removeTraceFSProbeEvent(typ, event); err != nil {
			return 0, fmt.Errorf("failed to remove spurious maxactive event: %s", err)
		}
		return 0, fmt.Errorf("create trace event with non-default maxactive: %w", ErrNotSupported)
	}
	if err != nil {
		return 0, fmt.Errorf("get trace event id: %w", err)
	}

	return tid, nil
}

// closeTraceFSProbeEvent removes the [k,u]probe with the given type, group and symbol
// from <tracefs>/[k,u]probe_events.
func closeTraceFSProbeEvent(typ tracefs.ProbeType, group, symbol string) error {
	pe := fmt.Sprintf("%s/%s", group, tracefs.SanitizeSymbol(symbol))
	return removeTraceFSProbeEvent(typ, pe)
}

func removeTraceFSProbeEvent(typ tracefs.ProbeType, pe string) error {
	f, err := typ.EventsFile()
	if err != nil {
		return err
	}
	defer f.Close()

	// See [k,u]probe_events syntax above. The probe type does not need to be specified
	// for removals.
	if _, err = f.WriteString("-:" + pe); err != nil {
		return fmt.Errorf("remove event %q from %s: %w", pe, f.Name(), err)
	}

	return nil
}
