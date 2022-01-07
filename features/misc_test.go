package features

import (
	"errors"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestInvalidMisc(t *testing.T) {
	if err := probeMisc(miscType(math.MaxUint32)); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Expected os.ErrInvalid but was: %v", err)
	}
}

func TestHaveMisc(t *testing.T) {
	tests := map[miscType]struct {
		probe     func() error
		minKernel string
	}{
		largeInsn:    {probe: HaveLargeInstructions, minKernel: "5.1"},
		boundedLoops: {probe: HaveBoundedLoops, minKernel: "5.2"},
		v2ISA:        {probe: HaveV2ISA, minKernel: "4.13"},
		v3ISA:        {probe: HaveV3ISA, minKernel: "5.0"},
	}

	for misc, test := range tests {
		test := test
		probe := fmt.Sprintf("misc-%d", misc)
		t.Run(probe, func(t *testing.T) {
			testutils.SkipOnOldKernel(t, test.minKernel, probe)

			if err := test.probe(); err != nil {
				t.Fatalf("Feature %s isn't supported even though kernel is at least %s: %v",
					probe, test.minKernel, err)
			}
		})
	}
}
