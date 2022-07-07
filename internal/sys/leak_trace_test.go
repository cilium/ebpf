package sys

import (
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func TestLeakTracers(t *testing.T) {
	c := qt.New(t)

	var tracers LeakTracers

	// Provide a buffered channel so we don't need to start a goroutine
	// for reading and checking the resulting event.
	tracer := &LeakTracer{C: make(chan *LeakTrace, 1)}
	tracer.close = func() {
		tracers.Remove(tracer)
	}
	tracers.Add(tracer)

	c.Assert(tracers.Count(), qt.Equals, 1)

	tracers.Trace(&FD{
		raw: 123,
		meta: &metadata{
			name:  "test",
			stack: []byte("stack"),
		},
	})

	select {
	case trace := <-tracer.C:
		c.Assert(trace.FD, qt.Equals, 123)
		c.Assert(trace.Name, qt.Equals, "test")
		c.Assert(trace.Stack, qt.Equals, "stack")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for a trace")
	}

	tracer.Close()

	c.Assert(tracers.Count(), qt.Equals, 0)
}
