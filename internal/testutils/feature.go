package testutils

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal"
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

func checkVersion(tb testing.TB, ufe *internal.UnsupportedFeatureError) {
	if ufe.MinimumVersion.Unspecified() {
		return
	}

	tb.Helper()

	if ignoreVersionCheck(tb.Name()) {
		tb.Logf("Skipping feature version check")
		return
	}

	if !isRuntimeVersionLessThan(tb, ufe.MinimumVersion, runtimeVersion(tb)) {
		tb.Fatalf("Feature '%s' isn't supported even though kernel is newer than %s",
			ufe.Name, ufe.MinimumVersion)
	}
}

func isRuntimeVersionLessThan(tb testing.TB, minv, runv internal.Version) bool {
	tb.Helper()

	if max := os.Getenv("CI_MAX_RUNTIME_VERSION"); max != "" {
		maxv, err := internal.NewVersion(max)
		if err != nil {
			tb.Fatalf("Invalid version %q in CI_MAX_RUNTIME_VERSION: %s", max, err)
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
