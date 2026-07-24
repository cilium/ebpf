package platform

import (
	"errors"
	"runtime"
	"strings"
)

const (
	Linux   = "linux"
	Windows = "windows"
)

// IsLinux and IsWindows identify the native BPF platform selected by the
// current build. This may differ from runtime.GOOS, for example on Android,
// which uses the Linux BPF platform.
const (
	IsLinux   = Native == Linux
	IsWindows = Native == Windows
)

// SelectVersion extracts the platform-appropriate version from a list of
// strings like `linux:6.1` or `windows:0.20.0`. Prefixes may identify either
// the target GOOS or its native BPF platform.
//
// Returns an empty string and nil if no version matched or an error if no strings were passed.
func SelectVersion(versions []string) (string, error) {
	return selectVersion(runtime.GOOS, Native, versions)
}

func selectVersion(goos, native string, versions []string) (string, error) {
	if len(versions) == 0 {
		return "", errors.New("no versions specified")
	}

	goosPrefix := goos + ":"
	nativePrefix := native + ":"

	for _, version := range versions {
		if after, ok := strings.CutPrefix(version, goosPrefix); ok {
			return after, nil
		}

		if native != "" && native != goos {
			if after, ok := strings.CutPrefix(version, nativePrefix); ok {
				return after, nil
			}
		}

		if native == Linux && !strings.ContainsRune(version, ':') {
			// Allow version numbers without a GOOS prefix on Linux.
			return version, nil
		}
	}

	return "", nil
}
