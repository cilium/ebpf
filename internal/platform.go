package internal

import (
	"fmt"
	"runtime"
)

// PlatformPrefix returns the platform-dependent syscall wrapper prefix used by
// the linux kernel.
//
// Based on https://github.com/golang/go/blob/master/src/go/build/syslist.go
// and https://github.com/libbpf/libbpf/blob/master/src/libbpf.c#L10047
func PlatformPrefix(symbol string) string {
	var prefix string
	switch runtime.GOARCH {
	case "386":
		prefix = "ia32"
	case "amd64", "amd64p32":
		prefix = "x64"

	case "arm", "armbe":
		prefix = "arm"
	case "arm64", "arm64be":
		prefix = "arm64"

	case "mips", "mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le":
		prefix = "mips"

	case "s390":
		prefix = "s390"
	case "s390x":
		prefix = "s390x"

	case "riscv", "riscv64":
		prefix = "riscv"

	case "ppc":
		prefix = "powerpc"
	case "ppc64", "ppc64le":
		prefix = "powerpc64"

	default:
		return ""
	}

	return fmt.Sprintf("__%s_%s", prefix, symbol)
}
