package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveMisc(t *testing.T) {
	tests := map[string]struct {
		typ       miscType
		probe     func() error
		minKernel string
	}{
		"large instructions": {typ: largeInsn, probe: HaveLargeInstructions, minKernel: "5.2"},
		"bounded loops":      {typ: boundedLoops, probe: HaveBoundedLoops, minKernel: "5.3"},
		"v2 ISA":             {typ: v2ISA, probe: HaveV2ISA, minKernel: "4.14"},
		"v3 ISA":             {typ: v3ISA, probe: HaveV3ISA, minKernel: "5.1"},
	}

	for misc, test := range tests {
		test := test
		t.Run(misc, func(t *testing.T) {
			testutils.SkipOnOldKernel(t, test.minKernel, misc)

			if err := test.probe(); err != nil {
				t.Fatalf("Feature %s isn't supported even though kernel is at least %s: %v",
					misc, test.minKernel, err)
			}
		})
	}
}
