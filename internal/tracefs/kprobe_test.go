package tracefs

import (
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

	// Prepare probe args.
	args := ProbeArgs{Type: Kprobe, Group: pg, Symbol: ksym}

	// Create a kprobe.
	kp, err := NewEvent(args)
	c.Assert(err, qt.IsNil)

	// Attempt to create an identical kprobe using tracefs,
	// expect it to fail with os.ErrExist.
	_, err = NewEvent(args)
	c.Assert(err, qt.ErrorIs, os.ErrExist,
		qt.Commentf("expected consecutive kprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kprobe.
	c.Assert(kp.Close(), qt.IsNil)

	args.Group = rg
	args.Ret = true

	// Same test for a kretprobe.
	krp, err := NewEvent(args)
	c.Assert(err, qt.IsNil)

	_, err = NewEvent(args)
	c.Assert(err, qt.ErrorIs, os.ErrExist,
		qt.Commentf("expected consecutive kretprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kretprobe.
	c.Assert(krp.Close(), qt.IsNil)
}
