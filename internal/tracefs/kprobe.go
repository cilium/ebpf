package tracefs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrInvalidInput = errors.New("invalid input")

	ErrInvalidMaxActive = errors.New("can only set maxactive on kretprobes")
)

type ProbeType uint8

const (
	KprobeType ProbeType = iota
	UprobeType
)

func (pt ProbeType) String() string {
	if pt == KprobeType {
		return "kprobe"
	}
	return "uprobe"
}

func (pt ProbeType) eventsFile() (*os.File, error) {
	path, err := sanitizeTracefsPath(fmt.Sprintf("%s_events", pt.String()))
	if err != nil {
		return nil, err
	}

	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
}

type ProbeArgs struct {
	Symbol, Group, Path          string
	Offset, RefCtrOffset, Cookie uint64
	Pid, RetprobeMaxActive       int
	Ret                          bool
}

// NewProbe creates a trace event by writing an entry to <tracefs>/[k,u]probe_events.
// A new trace event group name is generated on every call to support creating
// multiple trace events for the same kernel or userspace symbol.
// Path and offset are only set in the case of uprobe(s) and are used to set
// the executable/library path on the filesystem and the offset where the probe is inserted.
func NewProbe(typ ProbeType, args ProbeArgs) (uint64, string, error) {
	groupPrefix := "ebpf"
	if args.Group != "" {
		groupPrefix = args.Group
	}

	// Generate a random string for each trace event we attempt to create.
	// This value is used as the 'group' token in tracefs to allow creating
	// multiple kprobe trace events with the same name.
	group, err := RandomGroup(groupPrefix)
	if err != nil {
		return 0, "", fmt.Errorf("randomizing group name: %w", err)
	}
	args.Group = group

	// Create the [k,u]probe trace event using tracefs.
	tid, err := CreateTraceFSProbeEvent(typ, args)
	if err != nil {
		return 0, "", fmt.Errorf("creating probe entry on tracefs: %w", err)
	}

	return tid, args.Group, nil
}

// RandomGroup generates a pseudorandom string for use as a tracefs group name.
// Returns an error when the output string would exceed 63 characters (kernel
// limitation), when rand.Read() fails or when prefix contains characters not
// allowed by IsValidTraceID.
func RandomGroup(prefix string) (string, error) {
	if !IsValidTraceID(prefix) {
		return "", fmt.Errorf("prefix '%s' must be alphanumeric or underscore: %w", prefix, ErrInvalidInput)
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	group := fmt.Sprintf("%s_%x", prefix, b)
	if len(group) > 63 {
		return "", fmt.Errorf("group name '%s' cannot be longer than 63 characters: %w", group, ErrInvalidInput)
	}

	return group, nil
}

// IsValidTraceID implements the equivalent of a regex match
// against "^[a-zA-Z_][0-9a-zA-Z_]*$".
//
// Trace event groups, names and kernel symbols must adhere to this set
// of characters. Non-empty, first character must not be a number, all
// characters must be alphanumeric or underscore.
func IsValidTraceID(s string) bool {
	if len(s) < 1 {
		return false
	}
	for i, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '_':
		case i > 0 && c >= '0' && c <= '9':

		default:
			return false
		}
	}

	return true
}

func sanitizeTracefsPath(path ...string) (string, error) {
	base, err := getTracefsPath()
	if err != nil {
		return "", err
	}
	l := filepath.Join(path...)
	p := filepath.Join(base, l)
	if !strings.HasPrefix(p, base) {
		return "", fmt.Errorf("path '%s' attempts to escape base path '%s': %w", l, base, ErrInvalidInput)
	}
	return p, nil
}

// getTracefsPath will return a correct path to the tracefs mount point.
// Since kernel 4.1 tracefs should be mounted by default at /sys/kernel/tracing,
// but may be also be available at /sys/kernel/debug/tracing if debugfs is mounted.
// The available tracefs paths will depends on distribution choices.
var getTracefsPath = internal.Memoize(func() (string, error) {
	for _, p := range []struct {
		path   string
		fsType int64
	}{
		{"/sys/kernel/tracing", unix.TRACEFS_MAGIC},
		{"/sys/kernel/debug/tracing", unix.TRACEFS_MAGIC},
		// RHEL/CentOS
		{"/sys/kernel/debug/tracing", unix.DEBUGFS_MAGIC},
	} {
		if fsType, err := internal.FSType(p.path); err == nil && fsType == p.fsType {
			return p.path, nil
		}
	}

	return "", errors.New("neither debugfs nor tracefs are mounted")
})

// SanitizeSymbol replaces every invalid character for the tracefs api with an underscore.
// It is equivalent to calling regexp.MustCompile("[^a-zA-Z0-9]+").ReplaceAllString("_").
func SanitizeSymbol(s string) string {
	var skip bool
	return strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			skip = false
			return c

		case skip:
			return -1

		default:
			skip = true
			return '_'
		}
	}, s)
}

// GetTraceEventID reads a trace event's ID from tracefs given its group and name.
// The kernel requires group and name to be alphanumeric or underscore.
//
// name automatically has its invalid symbols converted to underscores so the caller
// can pass a raw symbol name, e.g. a kernel symbol containing dots.
func GetTraceEventID(group, name string) (uint64, error) {
	name = SanitizeSymbol(name)
	path, err := sanitizeTracefsPath("events", group, name, "id")
	if err != nil {
		return 0, err
	}
	tid, err := internal.ReadUint64FromFile("%d\n", path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err != nil {
		return 0, fmt.Errorf("reading trace event ID of %s/%s: %w", group, name, err)
	}

	return tid, nil
}

func probePrefix(ret bool, maxActive int) string {
	if ret {
		if maxActive > 0 {
			return fmt.Sprintf("r%d", maxActive)
		}
		return "r"
	}
	return "p"
}

// CreateTraceFSProbeEvent creates a new ephemeral trace event.
//
// Returns os.ErrNotExist if symbol is not a valid
// kernel symbol, or if it is not traceable with kprobes. Returns os.ErrExist
// if a probe with the same group and symbol already exists. Returns an error if
// args.RetprobeMaxActive is used on non kprobe types. Returns ErrNotSupported if
// the kernel is too old to support kretprobe maxactive.
func CreateTraceFSProbeEvent(typ ProbeType, args ProbeArgs) (uint64, error) {
	// Before attempting to create a trace event through tracefs,
	// check if an event with the same group and name already exists.
	// Kernels 4.x and earlier don't return os.ErrExist on writing a duplicate
	// entry, so we need to rely on reads for detecting uniqueness.
	_, err := GetTraceEventID(args.Group, args.Symbol)
	if err == nil {
		return 0, fmt.Errorf("trace event %s/%s: %w", args.Group, args.Symbol, os.ErrExist)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("checking trace event %s/%s: %w", args.Group, args.Symbol, err)
	}

	// Open the kprobe_events file in tracefs.
	f, err := typ.eventsFile()
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var pe, token string
	switch typ {
	case KprobeType:
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
			return 0, ErrInvalidMaxActive
		}
		token = KprobeToken(args)
		pe = fmt.Sprintf("%s:%s/%s %s", probePrefix(args.Ret, args.RetprobeMaxActive), args.Group, SanitizeSymbol(args.Symbol), token)
	case UprobeType:
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
			return 0, ErrInvalidMaxActive
		}
		token = UprobeToken(args)
		pe = fmt.Sprintf("%s:%s/%s %s", probePrefix(args.Ret, 0), args.Group, args.Symbol, token)
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
	tid, err := GetTraceEventID(args.Group, args.Symbol)
	if args.RetprobeMaxActive != 0 && errors.Is(err, os.ErrNotExist) {
		// Kernels < 4.12 don't support maxactive and therefore auto generate
		// group and event names from the symbol and offset. The symbol is used
		// without any sanitization.
		// See https://elixir.bootlin.com/linux/v4.10/source/kernel/trace/trace_kprobe.c#L712
		event := fmt.Sprintf("kprobes/r_%s_%d", args.Symbol, args.Offset)
		if err := removeTraceFSProbeEvent(typ, event); err != nil {
			return 0, fmt.Errorf("failed to remove spurious maxactive event: %s", err)
		}
		return 0, fmt.Errorf("create trace event with non-default maxactive: %w", internal.ErrNotSupported)
	}
	if err != nil {
		return 0, fmt.Errorf("get trace event id: %w", err)
	}

	return tid, nil
}

// CloseTraceFSProbeEvent removes the [k,u]probe with the given type, group and symbol
// from <tracefs>/[k,u]probe_events.
func CloseTraceFSProbeEvent(typ ProbeType, group, symbol string) error {
	pe := fmt.Sprintf("%s/%s", group, SanitizeSymbol(symbol))
	return removeTraceFSProbeEvent(typ, pe)
}

func removeTraceFSProbeEvent(typ ProbeType, pe string) error {
	f, err := typ.eventsFile()
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

// KprobeToken creates the SYM[+offs] token for the tracefs api.
func KprobeToken(args ProbeArgs) string {
	po := args.Symbol

	if args.Offset != 0 {
		po += fmt.Sprintf("+%#x", args.Offset)
	}

	return po
}
