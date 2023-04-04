package tracefs

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestKprobeTraceFSGroup(t *testing.T) {
	c := qt.New(t)

	// Expect <prefix>_<16 random hex chars>.
	g, err := RandomTraceFSGroup("ebpftest")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.Matches, `ebpftest_[a-f0-9]{16}`)

	// Expect error when the generator's output exceeds 63 characters.
	p := make([]byte, 47) // 63 - 17 (length of the random suffix and underscore) + 1
	for i := range p {
		p[i] = byte('a')
	}
	_, err = RandomTraceFSGroup(string(p))
	c.Assert(err, qt.Not(qt.IsNil))

	// Reject non-alphanumeric characters.
	_, err = RandomTraceFSGroup("/")
	c.Assert(err, qt.Not(qt.IsNil))
}
