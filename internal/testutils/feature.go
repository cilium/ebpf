package testutils

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
)

const (
	ignoreVersionEnvVar = "EBPF_TEST_IGNORE_VERSION"
)

func CheckFeatureTest(t *testing.T, fn func() error) {
	t.Helper()

	checkFeatureTestError(t, fn())
}

func checkFeatureTestError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		return
	}

	if errors.Is(err, internal.ErrNotSupportedOnOS) {
		t.Skip(err)
	}

	if ufe, ok := errors.AsType[*internal.UnsupportedFeatureError](err); ok {
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

	if ufe, ok := errors.AsType[*internal.UnsupportedFeatureError](err); ok {
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

	if IsVersionLessThan(tb, minVersion) {
		tb.Skipf("Test requires at least kernel %s (due to missing %s)", minVersion, feature)
	}
}

// Check whether the current runtime version is less than some minimum.
func IsVersionLessThan(tb testing.TB, minVersions ...string) bool {
	tb.Helper()

	version, err := platform.SelectVersion(minVersions)
	qt.Assert(tb, qt.IsNil(err))

	if version == "" {
		// No matching version means that the platform
		// doesn't support whatever feature.
		return true
	}

	minv, err := internal.NewVersion(version)
	if err != nil {
		tb.Fatalf("Invalid version %s: %s", version, err)
	}

	return isPlatformVersionLessThan(tb, minv, platformVersion(tb))
}

// isPlatformVersionLessThan reports whether the runtime version runv is less
// than the minimum version minv required by the calling test.
//
// Fails the test if it would never execute on CI at all: when the
// CI_MAX_RUNTIME env var is true, runv is the newest runtime available on CI,
// and requiring a version beyond it means the test is dead code.
func isPlatformVersionLessThan(tb testing.TB, minv, runv internal.Version) bool {
	tb.Helper()

	if !runv.Less(minv) {
		return false
	}

	// The leg running the newest runtime is the authority on dead tests:
	// a version-gated skip there means the test can never execute on CI.
	if max, _ := strconv.ParseBool(os.Getenv("CI_MAX_RUNTIME")); max {
		tb.Fatalf("Test for %s will never execute on CI since the newest runtime is %s", minv, runv)
	}

	return true
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

	ignored := strings.SplitSeq(tNames, ",")
	for n := range ignored {
		if strings.TrimSpace(n) == tName {
			return true
		}
	}
	return false
}

// SkipNonNativeEndian skips the test or benchmark if bo doesn't match the
// host's native endianness.
func SkipNonNativeEndian(tb testing.TB, bo binary.ByteOrder) {
	tb.Helper()

	if bo != internal.NativeEndian {
		tb.Skip("Skipping due to non-native endianness")
	}
}
