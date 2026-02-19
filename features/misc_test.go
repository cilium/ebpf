package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveLargeInstructions(t *testing.T) {
	testutils.CheckFeatureTest(t, haveLargeInstructions)
}

func TestHaveBoundedLoops(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBoundedLoops)
}

func TestHaveV2ISA(t *testing.T) {
	testutils.CheckFeatureTest(t, haveV2ISA)
}

func TestHaveV3ISA(t *testing.T) {
	testutils.CheckFeatureTest(t, haveV3ISA)
}

func TestHaveV4ISA(t *testing.T) {
	testutils.CheckFeatureTest(t, haveV4ISA)
}
