package testutils

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()
	tb.Logf("Ignoring version constraint %s for %s on %s", minVersion, feature, runtime.GOOS)
}

func IsKernelLessThan(tb testing.TB, minVersion string) bool {
	tb.Helper()
	tb.Logf("Ignoring version constraint %s on %s", minVersion, runtime.GOOS)
	return false
}

func runtimeVersion(tb testing.TB) internal.Version {
	// tb.Helper()
	// TODO(windows): We need a function which exposes the efW runtime version.
	// Probably need to contribute this upstream.
	tb.Fatal("not implemented yet")
	return internal.Version{}
}
