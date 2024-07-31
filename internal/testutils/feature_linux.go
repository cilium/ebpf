package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
)

// Deprecated: this method doesn't account for cross-platform differences.
func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()

	if IsKernelLessThan(tb, minVersion) {
		tb.Skipf("Test requires at least kernel %s (due to missing %s)", minVersion, feature)
	}
}

// Deprecated: this method doesn't account for cross-platform differences.
func IsKernelLessThan(tb testing.TB, minVersion string) bool {
	tb.Helper()

	minv, err := internal.NewVersion(minVersion)
	if err != nil {
		tb.Fatalf("Invalid version %s: %s", minVersion, err)
	}

	return isRuntimeVersionLessThan(tb, minv, runtimeVersion(tb))
}

func runtimeVersion(tb testing.TB) internal.Version {
	tb.Helper()

	v, err := linux.KernelVersion()
	if err != nil {
		tb.Fatal(err)
	}
	return v
}
