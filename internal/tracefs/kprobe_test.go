package tracefs

import (
	"errors"
	"fmt"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

// Global symbol, present on all tested kernels.
const ksym = "vprintk"

func TestKprobeTraceFSGroup(t *testing.T) {
	c := qt.New(t)

	// Expect <prefix>_<16 random hex chars>.
	g, err := RandomGroup("ebpftest")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.Matches, `ebpftest_[a-f0-9]{16}`)

	// Expect error when the generator's output exceeds 63 characters.
	p := make([]byte, 47) // 63 - 17 (length of the random suffix and underscore) + 1
	for i := range p {
		p[i] = byte('a')
	}
	_, err = RandomGroup(string(p))
	c.Assert(err, qt.Not(qt.IsNil))

	// Reject non-alphanumeric characters.
	_, err = RandomGroup("/")
	c.Assert(err, qt.Not(qt.IsNil))
}

func TestKprobeToken(t *testing.T) {
	tests := []struct {
		args     ProbeArgs
		expected string
	}{
		{ProbeArgs{Symbol: "symbol"}, "symbol"},
		{ProbeArgs{Symbol: "symbol", Offset: 1}, "symbol+0x1"},
		{ProbeArgs{Symbol: "symbol", Offset: 65535}, "symbol+0xffff"},
		{ProbeArgs{Symbol: "symbol", Offset: 65536}, "symbol+0x10000"},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			po := KprobeToken(tt.args)
			if tt.expected != po {
				t.Errorf("Expected symbol+offset to be '%s', got '%s'", tt.expected, po)
			}
		})
	}
}

// Test k(ret)probe creation writing directly to <tracefs>/kprobe_events.
func TestKprobeCreateTraceFS(t *testing.T) {
	c := qt.New(t)

	pg, _ := RandomGroup("ebpftest")
	rg, _ := RandomGroup("ebpftest")

	// Tee up cleanups in case any of the Asserts abort the function.
	defer func() {
		_ = CloseTraceFSProbeEvent(KprobeType, pg, ksym)
		_ = CloseTraceFSProbeEvent(KprobeType, rg, ksym)
	}()

	// Prepare probe args.
	args := ProbeArgs{Group: pg, Symbol: ksym}

	// Create a kprobe.
	_, err := CreateTraceFSProbeEvent(KprobeType, args)
	c.Assert(err, qt.IsNil)

	// Attempt to create an identical kprobe using tracefs,
	// expect it to fail with os.ErrExist.
	_, err = CreateTraceFSProbeEvent(KprobeType, args)
	c.Assert(errors.Is(err, os.ErrExist), qt.IsTrue,
		qt.Commentf("expected consecutive kprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kprobe.
	c.Assert(CloseTraceFSProbeEvent(KprobeType, pg, ksym), qt.IsNil)

	args.Group = rg
	args.Ret = true

	// Same test for a kretprobe.
	_, err = CreateTraceFSProbeEvent(KprobeType, args)
	c.Assert(err, qt.IsNil)

	_, err = CreateTraceFSProbeEvent(KprobeType, args)
	c.Assert(os.IsExist(err), qt.IsFalse,
		qt.Commentf("expected consecutive kretprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kretprobe.
	c.Assert(CloseTraceFSProbeEvent(KprobeType, rg, ksym), qt.IsNil)
}
