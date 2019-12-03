package internal

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/internal/unix"
	"github.com/pkg/errors"
)

// ErrorWithLog returns an error that includes logs from the
// kernel verifier.
//
// logErr should be the error returned by the syscall that generated
// the log. It is used to check for truncation of the output.
func ErrorWithLog(err error, log []byte, logErr error) error {
	detail := strings.TrimRight(CString(log), "\t\r\n ")
	if errors.Cause(logErr) == unix.ENOSPC {
		detail += " (truncated...)"
	}

	// The most specific information is usually at the end of
	// the log. Try to find the last line and try to use that
	// as the summary.
	var summary string
	if pos := strings.LastIndexByte(detail, '\n'); pos > 0 {
		summary = strings.TrimLeft(detail[pos:], "\t\r\n ")
	} else {
		summary = detail
		detail = ""
	}

	return &loadError{err, summary, detail}
}

type loadError struct {
	cause   error
	summary string
	detail  string
}

func (le *loadError) Error() string {
	if le.summary == "" {
		return le.cause.Error()
	}

	if le.detail == "" {
		return le.cause.Error() + ": " + le.summary
	}

	return fmt.Sprintf("%s: %s\n%s", le.cause, le.summary, le.detail)

}

func (le *loadError) Cause() error {
	return le.cause
}

// CString turns a NUL / zero terminated byte buffer into a string.
func CString(in []byte) string {
	inLen := bytes.IndexByte(in, 0)
	if inLen == -1 {
		return ""
	}
	return string(in[:inLen])
}
