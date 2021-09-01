package testutils

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func MustKernelVersion() internal.Version {
	v, err := internal.KernelVersion()
	if err != nil {
		panic(err)
	}
	return v
}

func CheckFeatureTest(t *testing.T, fn func() error) {
	t.Helper()

	err := fn()
	if err == nil {
		return
	}

	var ufe *internal.UnsupportedFeatureError
	if errors.As(err, &ufe) {
		checkKernelVersion(t, ufe)
	} else {
		t.Error("Feature test failed:", err)
	}
}

func SkipIfNotSupported(tb testing.TB, err error) {
	var ufe *internal.UnsupportedFeatureError
	if errors.As(err, &ufe) {
		checkKernelVersion(tb, ufe)
		tb.Skip(ufe.Error())
	}
	if errors.Is(err, internal.ErrNotSupported) {
		tb.Skip(err.Error())
	}
}

func checkKernelVersion(tb testing.TB, ufe *internal.UnsupportedFeatureError) {
	if ufe.MinimumVersion.Unspecified() {
		return
	}

	kernelVersion := MustKernelVersion()
	if ufe.MinimumVersion.Less(kernelVersion) {
		tb.Helper()
		tb.Fatalf("Feature '%s' isn't supported even though kernel %s is newer than %s",
			ufe.Name, kernelVersion, ufe.MinimumVersion)
	}
}

func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()

	minv, err := internal.NewVersion(minVersion)
	if err != nil {
		tb.Fatalf("Invalid version %s: %s", minVersion, err)
	}

	if MustKernelVersion().Less(minv) {
		tb.Skipf("Test requires at least kernel %s (due to missing %s)", minv, feature)
	}
}
