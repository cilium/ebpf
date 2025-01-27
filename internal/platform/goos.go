package platform

import "runtime"

const (
	IsLinux   = runtime.GOOS == "linux"
	IsWindows = runtime.GOOS == "windows"
)
