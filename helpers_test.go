package ebpf

import (
	"errors"
	"sync"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

var haveTestmod = sync.OnceValues(func() (bool, error) {
	// See https://github.com/torvalds/linux/commit/290248a5b7d829871b3ea3c62578613a580a1744
	testmod, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		return info.IsModule() && info.Name == "bpf_testmod"
	})
	if err != nil && !errors.Is(err, btf.ErrNotFound) {
		return false, err
	}
	testmod.Close()

	return testmod != nil, nil
})

func requireTestmod(tb testing.TB) {
	tb.Helper()

	testutils.SkipOnOldKernel(tb, "5.11", "bpf_testmod")

	testmod, err := haveTestmod()
	if err != nil {
		tb.Fatal(err)
	}
	if !testmod {
		tb.Skip("bpf_testmod not loaded")
	}
}
