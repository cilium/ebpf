package sys

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"
)

// FDs is a registry of all file descriptors wrapped into sys.FDs that were
// created while an fd tracer was active.
var FDs = newFDMap()

// Finalize is called when the Go runtime frees an [FD].
var Finalize FDTracer

// traceFDs returns true if there are active fd tracers registered to the
// package.
func traceFDs() bool {
	return Finalize != nil
}

type fdmap struct {
	mu sync.RWMutex
	m  map[int]FDTrace
}

func newFDMap() fdmap {
	return fdmap{
		m: make(map[int]FDTrace),
	}
}

func (fdm *fdmap) Get(key int) (FDTrace, bool) {
	fdm.mu.RLock()
	defer fdm.mu.RUnlock()

	v, ok := fdm.m[key]
	if !ok {
		return FDTrace{}, ok
	}

	return v, true
}

func (fdm *fdmap) Put(k int, value FDTrace) {
	fdm.mu.Lock()
	defer fdm.mu.Unlock()

	fdm.m[k] = value
}

func (fdm *fdmap) Delete(k int) {
	fdm.mu.Lock()
	defer fdm.mu.Unlock()

	delete(fdm.m, k)
}

func (fdm *fdmap) Len() int {
	fdm.mu.RLock()
	defer fdm.mu.RUnlock()

	return len(fdm.m)
}

func (fdm *fdmap) String() string {
	fdm.mu.RLock()
	defer fdm.mu.RUnlock()

	var b strings.Builder
	for _, trace := range fdm.m {
		b.WriteString(trace.String())
		b.WriteString("\n")
	}

	return b.String()
}

// FDTrace is an event passed to an [FDTracer].
type FDTrace struct {
	// The file descriptor assigned to the resource.
	FD int

	// Stack trace at the point the resource was created.
	Stack *runtime.Frames
}

func (t FDTrace) String() string {
	return fmt.Sprintf("fd %d created at:\n%s", t.FD, formatFrames(t.Stack))
}

// An FDTracer is a function receiving an [FDTrace].
// Assign it to [Finalize], etc.
type FDTracer func(FDTrace)

func (f FDTracer) do(fd *FD) {
	t, ok := FDs.Get(fd.Int())
	if !ok {
		return
	}

	f(t)
}

func callersFrames() *runtime.Frames {
	c := make([]uintptr, 32)
	for {
		// Skip runtime.Callers and this function.
		i := runtime.Callers(2, c)
		if i == 0 {
			return nil
		}
		if i < len(c) {
			return runtime.CallersFrames(c)
		}
		c = make([]uintptr, len(c)*2)
	}
}

func formatFrames(f *runtime.Frames) string {
	if f == nil {
		return ""
	}

	var b bytes.Buffer
	for {
		f, more := f.Next()
		b.WriteString(fmt.Sprintf("\t%s+%#x\n\t\t%s:%d\n", f.Function, f.PC-f.Entry, f.File, f.Line))
		if !more {
			break
		}
	}

	return b.String()
}
