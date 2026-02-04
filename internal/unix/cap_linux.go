//go:build linux

package unix

import (
	linux "golang.org/x/sys/unix"
)

const (
	LINUX_CAPABILITY_VERSION_3 = linux.LINUX_CAPABILITY_VERSION_3
	CAP_SYS_ADMIN              = linux.CAP_SYS_ADMIN
	CAP_BPF                    = linux.CAP_BPF
	CAP_PERFMON                = linux.CAP_PERFMON
)

type CapUserHeader = linux.CapUserHeader

type CapUserData struct {
	Effective   uint64
	Permitted   uint64
	Inheritable uint64
}

func Capget() (CapUserData, error) {
	var hdr = &CapUserHeader{
		Version: LINUX_CAPABILITY_VERSION_3,
	}

	var data [2]linux.CapUserData
	err := linux.Capget(hdr, &data[0])
	if err != nil {
		return CapUserData{}, err
	}

	return CapUserData{
		Effective:   uint64(data[0].Effective) | uint64(data[1].Effective)<<32,
		Permitted:   uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32,
		Inheritable: uint64(data[0].Inheritable) | uint64(data[1].Inheritable)<<32,
	}, err
}

func Capset(data CapUserData) error {
	var hdr = &CapUserHeader{
		Version: LINUX_CAPABILITY_VERSION_3,
	}

	var linuxData [2]linux.CapUserData
	linuxData[0].Effective = uint32(data.Effective & 0xFFFFFFFF)
	linuxData[0].Permitted = uint32(data.Permitted & 0xFFFFFFFF)
	linuxData[0].Inheritable = uint32(data.Inheritable & 0xFFFFFFFF)
	linuxData[1].Effective = uint32((data.Effective >> 32) & 0xFFFFFFFF)
	linuxData[1].Permitted = uint32((data.Permitted >> 32) & 0xFFFFFFFF)
	linuxData[1].Inheritable = uint32((data.Inheritable >> 32) & 0xFFFFFFFF)

	return linux.Capset(hdr, &linuxData[0])
}
