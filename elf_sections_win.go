package ebpf

type windowsElfSectionDef struct {
	pattern     string
	programType ProgramType
	attachType  AttachType
}

var windowsElfSectionDefs = []windowsElfSectionDef{
	// netebpfext\net_ebpf_ext_program_info.h
	{"xdp_test", WindowsXDPTest, AttachWindowsXDPTest},
	{"bind", WindowsBind, AttachWindowsBind},
	{"cgroup/connect4", WindowsCGroupSockAddr, AttachWindowsCGroupInet4Connect},
	{"cgroup/connect6", WindowsCGroupSockAddr, AttachWindowsCGroupInet6Connect},
	{"cgroup/recv_accept4", WindowsCGroupSockAddr, AttachWindowsCgroupInet4RecvAccept},
	{"cgroup/recv_accept6", WindowsCGroupSockAddr, AttachWindowsCgroupInet6RecvAccept},
	{"sockops", WindowsSockOps, AttachWindowsCGroupSockOps},
}
