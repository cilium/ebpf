package sys

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// LeakTracers represents a collection of leak tracers.
type LeakTracers struct {
	mu      sync.RWMutex
	tracers []*LeakTracer
}

// Count the amount of listening leak tracers in the collection.
func (lt *LeakTracers) Count() int {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	return len(lt.tracers)
}

// Add a LeakTracer.
func (lt *LeakTracers) Add(t *LeakTracer) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.tracers = append(lt.tracers, t)
}

// Remove a LeakTracer.
func (lt *LeakTracers) Remove(t *LeakTracer) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	for i, n := range lt.tracers {
		if n == t {
			lt.tracers[i] = lt.tracers[len(lt.tracers)-1]
			lt.tracers = lt.tracers[:len(lt.tracers)-1]
		}
	}
}

// Trace sends a LeakTrace to all tracers registered to the LeakTracers.
func (lt *LeakTracers) Trace(fd *FD) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	t := &LeakTrace{
		FD:    fd.raw,
		Name:  fd.Name(),
		Stack: fd.Stack(),
	}

	for _, tracer := range lt.tracers {
		select {
		case tracer.C <- t:
		default:
		}
	}
}

// LeakTrace is an event emitted to all registered leak tracers
// when the garbage collector closes an fd.
type LeakTrace struct {
	FD    int
	Name  string
	Stack string
}

func (lt *LeakTrace) String() string {
	return fmt.Sprintf("leaking file descriptor %d (%s) created at:\n%s", lt.FD, lt.Name, lt.Stack)
}

// LeakTracer is given to the caller as a means to receive leak notifications.
type LeakTracer struct {
	C     chan *LeakTrace
	close func()
}

// Close the tracer's channel and stop receiving traces over it.
func (t *LeakTracer) Close() {
	if t.close != nil {
		t.close()
	}
	close(t.C)
}

// Package-global collection of leak tracers to be notified when
// the garbage collector closes a file descriptor.
var leak LeakTracers

// HaveLeakTracers returns true if there are active leak tracers
// registered to the package.
func HaveLeakTracers() bool {
	return leak.Count() > 0
}

// NewLeakTracer returns and registers a new LeakTracer to the package.
func NewLeakTracer() *LeakTracer {
	tracer := &LeakTracer{C: make(chan *LeakTrace)}
	tracer.close = func() {
		leak.Remove(tracer)
	}

	leak.Add(tracer)
	return tracer
}

// NewLeakTraceExiter returns and registers a new LeakTracer to the package
// and starts a goroutine that calls os.Exit(1) when an fd leak occurs.
func NewLeakTraceExiter() *LeakTracer {
	tracer := NewLeakTracer()
	go func() {
		for {
			t, ok := <-tracer.C
			if !ok {
				break
			}
			fmt.Fprintln(os.Stderr, t.String())
			os.Exit(1)
		}
	}()

	return tracer
}

// TestMainWithTracing starts an fd leak tracer, runs the test suite, calls
// the garbage collector and exits the process with the return code obtained
// from the test suite.
func TestMainWithTracing(m *testing.M) {
	tracer := NewLeakTraceExiter()
	defer tracer.Close()

	code := m.Run()
	runtime.GC()
	// Finalizers are not guaranteed to have run when runtime.GC() returns.
	time.Sleep(100 * time.Millisecond)
	os.Exit(code)
}
