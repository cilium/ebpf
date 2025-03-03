package platform

import "runtime"

const (
	Linux = "linux"
)

const (
	IsLinux   = runtime.GOOS == "linux"
	IsWindows = runtime.GOOS == "windows"
)
