package features

import (
	"errors"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestFeatureInvalid(t *testing.T) {
	if err := Supports(MacroType(math.MaxUint32)); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Expected os.ErrInvalid but was: %v", err)
	}
}

func TestSupports(t *testing.T) {
	tests := map[MacroType]string{
		LargeInsn:    "5.1",
		BoundedLoops: "5.2",
		V2ISA:        "4.13",
		V3ISA:        "5.0",
	}

	for macro, minVersion := range tests {
		macro := macro
		minVersion := minVersion
		t.Run(macro.String(), func(t *testing.T) {
			testutils.SkipOnOldKernel(t, minVersion, macro.String())

			if err := Supports(macro); err != nil {
				t.Fatalf("Feature %s isn't supported even though kernel is at least %s: %v",
					macro.String(), minVersion, err)
			}
		})
	}
}
