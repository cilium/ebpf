package rlimit

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"

	"github.com/go-quicktest/qt"
)

func TestRemoveMemlock(t *testing.T) {
	var before unix.Rlimit
	qt.Assert(t, qt.IsNil(unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &before)))

	err := RemoveMemlock()
	qt.Assert(t, qt.IsNil(err))

	var after unix.Rlimit
	qt.Assert(t, qt.IsNil(unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &after)))

	// We can't use testutils here due to an import cycle.
	version, err := internal.KernelVersion()
	qt.Assert(t, qt.IsNil(err))

	if version.Less(unsupportedMemcgAccounting.MinimumVersion) {
		qt.Assert(t, qt.Equals(after.Cur, unix.RLIM_INFINITY), qt.Commentf("cur should be INFINITY"))
		qt.Assert(t, qt.Equals(after.Max, unix.RLIM_INFINITY), qt.Commentf("max should be INFINITY"))
	} else {
		qt.Assert(t, qt.Equals(after.Cur, before.Cur), qt.Commentf("cur should be unchanged"))
		qt.Assert(t, qt.Equals(after.Max, before.Max), qt.Commentf("max should be unchanged"))
	}
}
