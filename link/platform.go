package link

import "runtime"

func byArch(arch_map map[string]string) string {
	value, ok := arch_map[runtime.GOARCH]
	if !ok {
		panic("Unsupported arch " + runtime.GOARCH)
	}
	return value
}

func SysGetpid() string {
	_sys_getpid := map[string]string{
		"amd64": "__x64_sys_getpid",
		"arm64": "__arm64_sys_getpid",
	}

	return byArch(_sys_getpid)
}

func SysExecve() string {
	_sys_execve := map[string]string{
		"amd64": "__x64_sys_execve",
		"arm64": "__arm64_sys_execve",
	}

	return byArch(_sys_execve)
}
