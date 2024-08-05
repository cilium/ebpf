package ebpf

const (
	UnspecifiedMap MapType = iota
	Hash
	Array
	ProgramArray
	PerCPUHash
	PerCPUArray
	HashOfMaps
	ArrayOfMaps
	LRUHash
	LPMTrie
	Queue
	LRUCPUHash
	Stack
	RingBuf
)

const (
	PerfEventArray MapType = windowsUnsupportedTypeStart + iota
	StackTrace
	CGroupArray
	DevMap
	SockMap
	CPUMap
	XSKMap
	SockHash
	CGroupStorage
	ReusePortSockArray
	PerCPUCGroupStorage
	SkStorage
	DevMapHash
	StructOpsMap
	InodeStorage
	TaskStorage
)

// See https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_structs.h#L170
const (
	UnspecifiedProgram ProgramType = iota
	XDP
	CGroupSockAddr
	SockOps
	WinXDPTest ProgramType = 998
	WinSample  ProgramType = 999
)

// These program types are not supported on Windows.
const (
	SocketFilter ProgramType = windowsUnsupportedTypeStart + iota
	Kprobe
	SchedCLS
	SchedACT
	TracePoint
	PerfEvent
	CGroupSKB
	CGroupSock
	LWTIn
	LWTOut
	LWTXmit
	SkSKB
	CGroupDevice
	SkMsg
	RawTracepoint
	LWTSeg6Local
	LircMode2
	SkReuseport
	FlowDissector
	CGroupSysctl
	RawTracepointWritable
	CGroupSockopt
	Tracing
	StructOps
	Extension
	LSM
	SkLookup
	Syscall
	Netfilter
)

// See https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_structs.h#L260
const (
	AttachNone AttachType = iota
	AttachXDP
	AttachBind
	AttachCGroupInet4Connect
	AttachCGroupInet6Connect
	AttachCgroupInet4RecvAccept
	AttachCgroupInet6RecvAccept
	AttachCGroupSockOps
	AttachSample
	AttachXDPTest
)

// These attach types are not supported on Windows.
const (
	AttachCGroupInetIngress AttachType = 1_000_000 + iota
	AttachCGroupInetEgress
	AttachCGroupInetSockCreate
	AttachSkSKBStreamParser
	AttachSkSKBStreamVerdict
	AttachCGroupDevice
	AttachSkMsgVerdict
	AttachCGroupInet4Bind
	AttachCGroupInet6Bind
	AttachCGroupInet4PostBind
	AttachCGroupInet6PostBind
	AttachCGroupUDP4Sendmsg
	AttachCGroupUDP6Sendmsg
	AttachLircMode2
	AttachFlowDissector
	AttachCGroupSysctl
	AttachCGroupUDP4Recvmsg
	AttachCGroupUDP6Recvmsg
	AttachCGroupGetsockopt
	AttachCGroupSetsockopt
	AttachTraceRawTp
	AttachTraceFEntry
	AttachTraceFExit
	AttachModifyReturn
	AttachLSMMac
	AttachTraceIter
	AttachCgroupInet4GetPeername
	AttachCgroupInet6GetPeername
	AttachCgroupInet4GetSockname
	AttachCgroupInet6GetSockname
	AttachXDPDevMap
	AttachCgroupInetSockRelease
	AttachXDPCPUMap
	AttachSkLookup
	AttachSkSKBVerdict
	AttachSkReuseportSelect
	AttachSkReuseportSelectOrMigrate
	AttachPerfEvent
	AttachTraceKprobeMulti
	AttachLSMCgroup
	AttachStructOps
	AttachNetfilter
	AttachTCXIngress
	AttachTCXEgress
	AttachTraceUprobeMulti
	AttachCgroupUnixConnect
	AttachCgroupUnixSendmsg
	AttachCgroupUnixRecvmsg
	AttachCgroupUnixGetpeername
	AttachCgroupUnixGetsockname
	AttachNetkitPrimary
	AttachNetkitPeer
)
