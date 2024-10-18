package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveSyscallWrapper(t *testing.T) {
	testutils.CheckFeatureTest(t, haveSyscallWrapper)
}
