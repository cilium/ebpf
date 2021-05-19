package main

import (
	"os"
	"runtime"
)

func goBuildArch() string {
	value, found := os.LookupEnv("GOARCH")

	if !found {
		return runtime.GOARCH
	}

	return value
}

// get the target arch as defined in linux/tools/lib/bpf/bpf_tracing.h
func getTargetArch() string {
	switch goBuildArch() {
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
		return ""
	}
}

func addTargetArchToCflags(cflags []string) []string {
	targetArch := getTargetArch()
	if targetArch != "" {
		cflags = append([]string{"-D" + targetArch}, cflags...)
	}

	return cflags
}
