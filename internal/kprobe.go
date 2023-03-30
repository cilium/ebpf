package internal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

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
