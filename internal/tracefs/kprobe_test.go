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

func TestNewEvent(t *testing.T) {
	for _, args := range []ProbeArgs{
		{Type: Kprobe, Symbol: ksym},
		{Type: Kprobe, Symbol: ksym, Ret: true},
		{Type: Uprobe, Path: "/bin/bash", Symbol: "main"},
		{Type: Uprobe, Path: "/bin/bash", Symbol: "main", Ret: true},
	} {
		name := fmt.Sprintf("%s ret=%v", args.Type, args.Ret)
		t.Run(name, func(t *testing.T) {
			args.Group, _ = RandomGroup("ebpftest")

			evt, err := NewEvent(args)
			qt.Assert(t, err, qt.IsNil)
			defer evt.Close()

			_, err = NewEvent(args)
			qt.Assert(t, err, qt.ErrorIs, os.ErrExist,
				qt.Commentf("expected consecutive event creation to contain os.ErrExist"))

			qt.Assert(t, evt.Close(), qt.IsNil)
			qt.Assert(t, evt.Close(), qt.ErrorIs, os.ErrClosed)
		})
	}
}
