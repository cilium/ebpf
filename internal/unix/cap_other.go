//go:build !linux

package unix

const (
	LINUX_CAPABILITY_VERSION_3 = 0
	CAP_SYS_ADMIN
	CAP_BPF
	CAP_PERFMON
)

type CapUserHeader struct {
	Version uint32
	Pid     int32
}

type CapUserData struct {
	Effective   uint64
	Permitted   uint64
	Inheritable uint64
}

func Capget() (CapUserData, error) {
	return CapUserData{}, errNonLinux()
}

func Capset(data CapUserData) error {
	return errNonLinux()
}
