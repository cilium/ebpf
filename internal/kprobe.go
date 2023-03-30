package internal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrInvalidInput = errors.New("invalid input")
)

// RandomTraceFSGroup generates a pseudorandom string for use as a tracefs group name.
// Returns an error when the output string would exceed 63 characters (kernel
// limitation), when rand.Read() fails or when prefix contains characters not
// allowed by IsValidTraceID.
func RandomTraceFSGroup(prefix string) (string, error) {
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

func SanitizeTracefsPath(path ...string) (string, error) {
	base, err := GetTracefsPath()
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

// GetTracefsPath will return a correct path to the tracefs mount point.
// Since kernel 4.1 tracefs should be mounted by default at /sys/kernel/tracing,
// but may be also be available at /sys/kernel/debug/tracing if debugfs is mounted.
// The available tracefs paths will depends on distribution choices.
var GetTracefsPath = Memoize(func() (string, error) {
	for _, p := range []struct {
		path   string
		fsType int64
	}{
		{"/sys/kernel/tracing", unix.TRACEFS_MAGIC},
		{"/sys/kernel/debug/tracing", unix.TRACEFS_MAGIC},
		// RHEL/CentOS
		{"/sys/kernel/debug/tracing", unix.DEBUGFS_MAGIC},
	} {
		if fsType, err := FSType(p.path); err == nil && fsType == p.fsType {
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
	path, err := SanitizeTracefsPath("events", group, name, "id")
	if err != nil {
		return 0, err
	}
	tid, err := ReadUint64FromFile("%d\n", path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err != nil {
		return 0, fmt.Errorf("reading trace event ID of %s/%s: %w", group, name, err)
	}

	return tid, nil
}

func ProbePrefix(ret bool, maxActive int) string {
	if ret {
		if maxActive > 0 {
			return fmt.Sprintf("r%d", maxActive)
		}
		return "r"
	}
	return "p"
}

// OpenTracepointPerfEvent opens a tracepoint-type perf event. System-wide
// [k,u]probes created by writing to <tracefs>/[k,u]probe_events are tracepoints
// behind the scenes, and can be attached to using these perf events.
func OpenTracepointPerfEvent(tid uint64, pid int) (*sys.FD, error) {
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      tid,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(&attr, pid, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("opening tracepoint perf event: %w", err)
	}

	return sys.NewFD(fd)
}
