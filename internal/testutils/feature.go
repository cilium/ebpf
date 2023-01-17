package testutils

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func CheckFeatureTest(t *testing.T, fn func() error) {
	checkFeatureTestError(t, fn())
}

func checkFeatureTestError(t *testing.T, err error) {
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

func CheckFeatureMatrix[K comparable](t *testing.T, fm internal.FeatureMatrix[K]) {
	t.Helper()

	for key, ft := range fm {
		t.Run(ft.Name, func(t *testing.T) {
			checkFeatureTestError(t, fm.Result(key))
		})
	}
}

func SkipIfNotSupported(tb testing.TB, err error) {
	tb.Helper()

	if err == internal.ErrNotSupported {
		tb.Fatal("Unwrapped ErrNotSupported")
	}

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

	if !isKernelLessThan(tb, ufe.MinimumVersion) {
		tb.Helper()
		tb.Fatalf("Feature '%s' isn't supported even though kernel is newer than %s",
			ufe.Name, ufe.MinimumVersion)
	}
}

func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()

	if IsKernelLessThan(tb, minVersion) {
		tb.Skipf("Test requires at least kernel %s (due to missing %s)", minVersion, feature)
	}
}

func IsKernelLessThan(tb testing.TB, minVersion string) bool {
	tb.Helper()

	minv, err := internal.NewVersion(minVersion)
	if err != nil {
		tb.Fatalf("Invalid version %s: %s", minVersion, err)
	}

	return isKernelLessThan(tb, minv)
}

func isKernelLessThan(tb testing.TB, minv internal.Version) bool {
	tb.Helper()

	if max := os.Getenv("CI_MAX_KERNEL_VERSION"); max != "" {
		maxv, err := internal.NewVersion(max)
		if err != nil {
			tb.Fatalf("Invalid version %q in CI_MAX_KERNEL_VERSION: %s", max, err)
		}

		if maxv.Less(minv) {
			tb.Fatalf("Test for %s will never execute on CI since %s is the most recent kernel", minv, maxv)
		}
	}

	return kernelVersion(tb).Less(minv)
}

func kernelVersion(tb testing.TB) internal.Version {
	tb.Helper()

	v, err := internal.KernelVersion()
	if err != nil {
		tb.Fatal(err)
	}
	return v
}
