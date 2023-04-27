package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func haveTestmod(tb testing.TB) bool {
	haveTestmod := false
	if !testutils.IsKernelLessThan(tb, "5.11") {
		// See https://github.com/torvalds/linux/commit/290248a5b7d829871b3ea3c62578613a580a1744
		testmod, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
			return info.IsModule() && info.Name == "bpf_testmod"
		})
		if err != nil && !errors.Is(err, btf.ErrNotFound) {
			tb.Fatal(err)
		}
		haveTestmod = testmod != nil
		testmod.Close()
	}

	return haveTestmod
}
