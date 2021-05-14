package internal

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"

	"golang.org/x/sys/unix"
)

// from https://github.com/iovisor/gobpf/blob/master/elf/kernel_version.go
// and https://github.com/google/cadvisor/pull/1786/files

var versionRegex = regexp.MustCompile(`^(\d+)\.(\d+).(\d+).*$`)

// KernelVersionFromReleaseString converts a release string with format
// 4.4.2[-1] to a kernel version number in LINUX_VERSION_CODE format.
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func kernelVersionFromReleaseString(releaseString string) (uint32, error) {
	versionParts := versionRegex.FindStringSubmatch(releaseString)
	if len(versionParts) != 4 {
		return 0, fmt.Errorf("got invalid release version %q (expected format '4.3.2-1')", releaseString)
	}
	major, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return 0, err
	}

	minor, err := strconv.Atoi(versionParts[2])
	if err != nil {
		return 0, err
	}

	patch, err := strconv.Atoi(versionParts[3])
	if err != nil {
		return 0, err
	}
	out := major*256*256 + minor*256 + patch
	return uint32(out), nil
}

// Gets a converted release string with format 4.4.2[-1] to a kernel version
// number in LINUX_VERSION_CODE format.
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func CurrentKernelVersion() (uint32, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, err
	}
	releaseString := string(uname.Release[:bytes.IndexByte(uname.Release[:], 0)])
	return kernelVersionFromReleaseString(releaseString)
}
