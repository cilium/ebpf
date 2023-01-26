package sys

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// Create is called when a new [FD] is created.
var Create Tracer

// Close is called when a [FD.Close] is called explicitly.
var Close Tracer

// Finalize is called when the Go runtime frees an [FD].
var Finalize Tracer

// tracing returns true if there are active fd tracers registered to the
// package.
func tracing() bool {
	return Create != nil || Close != nil || Finalize != nil
}

// Tracer can be assigned to one of Create, Close or Finalize.
type Tracer func(Trace)

func (t Tracer) do(fd *FD) {
	m := fdMeta[fd.Int()]
	if m == nil {
		return
	}

	if t == nil {
		return
	}

	t(Trace{
		FD:    fd.raw,
		Name:  m.name,
		Stack: m.stack,
	})
}

// Trace is an event passed to a Tracer.
type Trace struct {
	FD    int
	Name  string
	Stack *runtime.Frames
}

func (t Trace) String() string {
	return fmt.Sprintf("fd %d, name '%s': created at:\n%s", t.FD, t.Name, formatFrames(t.Stack))
}

// TraceTestMain registers an fd leak tracer, runs the test suite, triggers
// garbage collection and exits the process with the return code obtained
// from the test suite.
func TraceTestMain(m *testing.M) {
	Finalize = Exiter

	ret := m.Run()

	if len(fdMeta) > 0 {
		fmt.Fprintln(os.Stderr, "leaked file descriptors:")
		for fd, meta := range fdMeta {
			fmt.Fprintf(os.Stderr, "fd %d, %s", fd, meta.String())
		}
		os.Exit(1)
	}

	Finalize = nil

	os.Exit(ret)
}

// Exiter prints t and exits the application with return code 1.
func Exiter(t Trace) {
	fmt.Fprintln(os.Stderr, "closed by gc:", t)
	os.Exit(1)
}
