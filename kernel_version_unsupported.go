// +build !linux

package ebpf

import (
	"fmt"

	"runtime"
)

var ErrNonLinux = fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)

func KernelVersionFromReleaseString(releaseString string) (uint32, error) {
	return 0, ErrNonLinux
}

func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNonLinux
}
