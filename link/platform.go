package link

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"

	"github.com/cilium/ebpf/internal"
)

const (
	// Since 4.17, syscalls symbols are generated with the `__x64_` prefix.
	// https://github.com/torvalds/linux/commit/d5a00528b58cdb2c71206e18bd021e34c4eab878
	LinuxVersionWithPrefix = 4<<16 + 17<<8 + 0
)

var parseArchSyscall = regexp.MustCompile(`__(\w*)_sys_(\w*)`)
var parseSyscall = regexp.MustCompile(`sys_(\w*)`)

func ResolveSyscall(syscall string) (string, error) {
	_, resolved, err := resolveArchSyscall(syscall)
	if err == nil {
		return formatResolvedSyscall(resolved), nil
	}

	resolved, err = resolveSyscall(syscall)
	if err == nil {
		return formatResolvedSyscall(resolved), nil
	}

	return "", fmt.Errorf("Unable to parse %s: %v", syscall, err)
}

func resolveArchSyscall(syscall string) (string, string, error) {
	match := parseArchSyscall.FindStringSubmatch(syscall)
	if len(match) != 3 {
		return "", "", errors.New("Not an arch syscall")
	}
	return match[1], match[2], nil
}

func resolveSyscall(syscall string) (string, error) {
	match := parseSyscall.FindStringSubmatch(syscall)
	if len(match) != 2 {
		return "", errors.New("Uknown syscall name format")
	}
	return match[1], nil
}

func formatResolvedSyscall(resolved string) string {

	kernelVersion, err := internal.CurrentKernelVersion()

	if err == nil && kernelVersion < LinuxVersionWithPrefix {
		return fmt.Sprintf("sys_%s", resolved)
	}

	prefix := runtime.GOARCH
	switch prefix {
	case "i386":
		prefix = "ia32"
	case "amd64":
		prefix = "x64"
	}

	return fmt.Sprintf("__%s_sys_%s", prefix, resolved)
}
