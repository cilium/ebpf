package rlimit

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

func TestRemoveMemlock(t *testing.T) {
	var before unix.Rlimit
	qt.Assert(t, unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &before), qt.IsNil)

	err := RemoveMemlock()
	qt.Assert(t, err, qt.IsNil)

	var after unix.Rlimit
	qt.Assert(t, unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &after), qt.IsNil)

	// We can't use testutils here due to an import cycle.
	version, err := internal.KernelVersion()
	qt.Assert(t, err, qt.IsNil)

	if version.Less(unsupportedMemcgAccounting.MinimumVersion) {
		qt.Assert(t, after.Cur, qt.Equals, uint64(unix.RLIM_INFINITY), qt.Commentf("cur should be INFINITY"))
		qt.Assert(t, after.Max, qt.Equals, uint64(unix.RLIM_INFINITY), qt.Commentf("max should be INFINITY"))
	} else {
		qt.Assert(t, after.Cur, qt.Equals, before.Cur, qt.Commentf("cur should be unchanged"))
		qt.Assert(t, after.Max, qt.Equals, before.Max, qt.Commentf("max should be unchanged"))
	}
}
