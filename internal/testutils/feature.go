package testutils

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
)

const (
	ignoreVersionEnvVar = "EBPF_TEST_IGNORE_VERSION"
)

func CheckFeatureTest(t *testing.T, fn func() error) {
	checkFeatureTestError(t, fn())
}

func checkFeatureTestError(t *testing.T, err error) {
	if err == nil {
		return
	}

	if errors.Is(err, internal.ErrNotSupportedOnOS) {
		t.Skip(err)
	}

	var ufe *internal.UnsupportedFeatureError
	if errors.As(err, &ufe) {
		checkVersion(t, ufe)
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
		checkVersion(tb, ufe)
		tb.Skip(ufe.Error())
	}
	if errors.Is(err, internal.ErrNotSupported) {
		tb.Skip(err.Error())
	}
}

func SkipIfNotSupportedOnOS(tb testing.TB, err error) {
	tb.Helper()

	if err == internal.ErrNotSupportedOnOS {
		tb.Fatal("Unwrapped ErrNotSupportedOnOS")
	}

	if errors.Is(err, internal.ErrNotSupportedOnOS) {
		tb.Skip(err.Error())
	}
}

func checkVersion(tb testing.TB, ufe *internal.UnsupportedFeatureError) {
	if ufe.MinimumVersion.Unspecified() {
		return
	}

	tb.Helper()

	if ignoreVersionCheck(tb.Name()) {
		tb.Logf("Ignoring error due to %s: %s", ignoreVersionEnvVar, ufe.Error())
		return
	}

	if !isPlatformVersionLessThan(tb, ufe.MinimumVersion, platformVersion(tb)) {
		tb.Fatalf("Feature '%s' isn't supported even though kernel is newer than %s",
			ufe.Name, ufe.MinimumVersion)
	}
}

// Skip a test based on the Linux version we are running on.
//
// Warning: this function does not have an effect on platforms other than Linux.
func SkipOnOldKernel(tb testing.TB, minVersion, feature string) {
	tb.Helper()

	if !platform.IsLinux {
		tb.Logf("Ignoring version constraint %s for %s on %s", minVersion, feature, runtime.GOOS)
		return
	}

	if IsKernelLessThan(tb, minVersion) {
		tb.Skipf("Test requires at least kernel %s (due to missing %s)", minVersion, feature)
	}
}

// Check whether the running Linux version is smaller than a specific version.
//
// Warning: this function always returns false on platforms other than Linux.
func IsKernelLessThan(tb testing.TB, minVersion string) bool {
	tb.Helper()

	if !platform.IsLinux {
		tb.Logf("Ignoring version constraint %s on %s", minVersion, runtime.GOOS)
		return false
	}

	minv, err := internal.NewVersion(minVersion)
	if err != nil {
		tb.Fatalf("Invalid version %s: %s", minVersion, err)
	}

	return isPlatformVersionLessThan(tb, minv, platformVersion(tb))
}

func isPlatformVersionLessThan(tb testing.TB, minv, runv internal.Version) bool {
	tb.Helper()

	key := "CI_MAX_KERNEL_VERSION"
	if platform.IsWindows {
		key = "CI_MAX_EFW_VERSION"
	}

	if max := os.Getenv(key); max != "" {
		maxv, err := internal.NewVersion(max)
		if err != nil {
			tb.Fatalf("Invalid version %q in %s: %s", max, key, err)
		}

		if maxv.Less(minv) {
			tb.Fatalf("Test for %s will never execute on CI since %s is the most recent runtime", minv, maxv)
		}
	}

	return runv.Less(minv)
}

// ignoreVersionCheck checks whether to omit the version check for a test.
//
// It reads a comma separated list of test names from an environment variable.
//
// For example:
//
//	EBPF_TEST_IGNORE_VERSION=TestABC,TestXYZ go test ...
func ignoreVersionCheck(tName string) bool {
	tNames := os.Getenv(ignoreVersionEnvVar)
	if tNames == "" {
		return false
	}

	ignored := strings.Split(tNames, ",")
	for _, n := range ignored {
		if strings.TrimSpace(n) == tName {
			return true
		}
	}
	return false
}

var featureTestOverride sync.Mutex

// DisableFeatureTests causes the execution of a feature test to fail the unit test.
//
// This must not be called concurrently.
//
// The returned function may be called to re-enable feature tests before the
// end of the test.
func DisableFeatureTests(tb testing.TB) func() {
	tb.Helper()

	featureTestOverride.Lock()
	defer featureTestOverride.Unlock()

	if internal.FeatureTestOverride != nil {
		tb.Fatal("There is already a feature test override in place")
	}

	internal.FeatureTestOverride = func(name string) error {
		tb.Fatalf("Probe for %q executed while feature tests are disabled", name)
		return errors.New("feature tests are disabled")
	}

	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}

		featureTestOverride.Lock()
		defer featureTestOverride.Unlock()

		cleaned = true
		internal.FeatureTestOverride = nil
	}
	tb.Cleanup(cleanup)

	return cleanup
}
