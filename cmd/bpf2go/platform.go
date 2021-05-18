package main

import "runtime"

func getTargetArch() string {
	if runtime.GOOS != "linux" {
		panic("Not supported platform " + runtime.GOOS)
	}

	switch runtime.GOARCH {
	case "386", "amd64":
		return "__TARGET_ARCH_x86"
	case "s390", "s390x":
		return "__TARGET_ARCH_s390"
	case "arm":
		return "__TARGET_ARCH_arm"
	case "arm64":
		return "__TARGET_ARCH_arm64"
	case "mipsle", "mips", "mips64", "mips64le":
		return "__TARGET_ARCH_mips"
	case "ppc64", "ppc64le":
		return "__TARGET_ARCH_powerpc"
	default:
		panic("Not supported platform " + runtime.GOARCH)
	}
}
