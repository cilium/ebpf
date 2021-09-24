package internal_test

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
	qt "github.com/frankban/quicktest"
)

func TestRemoveMemlockRlimit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "memcg accounting")

	var before unix.Rlimit
	qt.Assert(t, unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &before), qt.IsNil)

	err := internal.RemoveMemlockRlimit()
	qt.Assert(t, err, qt.IsNil)

	var after unix.Rlimit
	qt.Assert(t, unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &after), qt.IsNil)

	if testutils.MustKernelVersion().Less(internal.Version{5, 11, 0}) {
		qt.Assert(t, after.Cur, qt.Equals, uint64(unix.RLIM_INFINITY), qt.Commentf("cur should be INFINITY"))
		qt.Assert(t, after.Max, qt.Equals, uint64(unix.RLIM_INFINITY), qt.Commentf("max should be INFINITY"))
	} else {
		qt.Assert(t, after.Cur, qt.Equals, before.Cur, qt.Commentf("cur should be unchanged"))
		qt.Assert(t, after.Max, qt.Equals, before.Max, qt.Commentf("max should be unchanged"))
	}

}
