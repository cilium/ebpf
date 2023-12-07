package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveLargeInstructions(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveLargeInstructions)
}

func TestHaveBoundedLoops(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveBoundedLoops)
}

func TestHaveV2ISA(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveV2ISA)
}

func TestHaveV3ISA(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveV3ISA)
}
