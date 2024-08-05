package ebpf

import (
	"github.com/cilium/ebpf/internal/sys"
)

// All the various map types that can be created
const (
	UnspecifiedMap MapType = iota
	// Hash is a hash map
	Hash
	// Array is an array map
	Array
	// ProgramArray - A program array map is a special kind of array map whose map
	// values contain only file descriptors referring to other eBPF
	// programs.  Thus, both the key_size and value_size must be
	// exactly four bytes.  This map is used in conjunction with the
	// TailCall helper.
	ProgramArray
	// PerfEventArray - A perf event array is used in conjunction with PerfEventRead
	// and PerfEventOutput calls, to read the raw bpf_perf_data from the registers.
	PerfEventArray
	// PerCPUHash - This data structure is useful for people who have high performance
	// network needs and can reconcile adds at the end of some cycle, so that
	// hashes can be lock free without the use of XAdd, which can be costly.
	PerCPUHash
	// PerCPUArray - This data structure is useful for people who have high performance
	// network needs and can reconcile adds at the end of some cycle, so that
	// hashes can be lock free without the use of XAdd, which can be costly.
	// Each CPU gets a copy of this hash, the contents of all of which can be reconciled
	// later.
	PerCPUArray
	// StackTrace - This holds whole user and kernel stack traces, it can be retrieved with
	// GetStackID
	StackTrace
	// CGroupArray - This is a very niche structure used to help SKBInCGroup determine
	// if an skb is from a socket belonging to a specific cgroup
	CGroupArray
	// LRUHash - This allows you to create a small hash structure that will purge the
	// least recently used items rather than throw an error when you run out of memory
	LRUHash
	// LRUCPUHash - This is NOT like PerCPUHash, this structure is shared among the CPUs,
	// it has more to do with including the CPU id with the LRU calculation so that if a
	// particular CPU is using a value over-and-over again, then it will be saved, but if
	// a value is being retrieved a lot but sparsely across CPUs it is not as important, basically
	// giving weight to CPU locality over overall usage.
	LRUCPUHash
	// LPMTrie - This is an implementation of Longest-Prefix-Match Trie structure. It is useful,
	// for storing things like IP addresses which can be bit masked allowing for keys of differing
	// values to refer to the same reference based on their masks. See wikipedia for more details.
	LPMTrie
	// ArrayOfMaps - Each item in the array is another map. The inner map mustn't be a map of maps
	// itself.
	ArrayOfMaps
	// HashOfMaps - Each item in the hash map is another map. The inner map mustn't be a map of maps
	// itself.
	HashOfMaps
	// DevMap - Specialized map to store references to network devices.
	DevMap
	// SockMap - Specialized map to store references to sockets.
	SockMap
	// CPUMap - Specialized map to store references to CPUs.
	CPUMap
	// XSKMap - Specialized map for XDP programs to store references to open sockets.
	XSKMap
	// SockHash - Specialized hash to store references to sockets.
	SockHash
	// CGroupStorage - Special map for CGroups.
	CGroupStorage
	// ReusePortSockArray - Specialized map to store references to sockets that can be reused.
	ReusePortSockArray
	// PerCPUCGroupStorage - Special per CPU map for CGroups.
	PerCPUCGroupStorage
	// Queue - FIFO storage for BPF programs.
	Queue
	// Stack - LIFO storage for BPF programs.
	Stack
	// SkStorage - Specialized map for local storage at SK for BPF programs.
	SkStorage
	// DevMapHash - Hash-based indexing scheme for references to network devices.
	DevMapHash
	// StructOpsMap - This map holds a kernel struct with its function pointer implemented in a BPF
	// program.
	StructOpsMap
	// RingBuf - Similar to PerfEventArray, but shared across all CPUs.
	RingBuf
	// InodeStorage - Specialized local storage map for inodes.
	InodeStorage
	// TaskStorage - Specialized local storage map for task_struct.
	TaskStorage
)

// eBPF program types
const (
	UnspecifiedProgram    = ProgramType(sys.BPF_PROG_TYPE_UNSPEC)
	SocketFilter          = ProgramType(sys.BPF_PROG_TYPE_SOCKET_FILTER)
	Kprobe                = ProgramType(sys.BPF_PROG_TYPE_KPROBE)
	SchedCLS              = ProgramType(sys.BPF_PROG_TYPE_SCHED_CLS)
	SchedACT              = ProgramType(sys.BPF_PROG_TYPE_SCHED_ACT)
	TracePoint            = ProgramType(sys.BPF_PROG_TYPE_TRACEPOINT)
	XDP                   = ProgramType(sys.BPF_PROG_TYPE_XDP)
	PerfEvent             = ProgramType(sys.BPF_PROG_TYPE_PERF_EVENT)
	CGroupSKB             = ProgramType(sys.BPF_PROG_TYPE_CGROUP_SKB)
	CGroupSock            = ProgramType(sys.BPF_PROG_TYPE_CGROUP_SOCK)
	LWTIn                 = ProgramType(sys.BPF_PROG_TYPE_LWT_IN)
	LWTOut                = ProgramType(sys.BPF_PROG_TYPE_LWT_OUT)
	LWTXmit               = ProgramType(sys.BPF_PROG_TYPE_LWT_XMIT)
	SockOps               = ProgramType(sys.BPF_PROG_TYPE_SOCK_OPS)
	SkSKB                 = ProgramType(sys.BPF_PROG_TYPE_SK_SKB)
	CGroupDevice          = ProgramType(sys.BPF_PROG_TYPE_CGROUP_DEVICE)
	SkMsg                 = ProgramType(sys.BPF_PROG_TYPE_SK_MSG)
	RawTracepoint         = ProgramType(sys.BPF_PROG_TYPE_RAW_TRACEPOINT)
	CGroupSockAddr        = ProgramType(sys.BPF_PROG_TYPE_CGROUP_SOCK_ADDR)
	LWTSeg6Local          = ProgramType(sys.BPF_PROG_TYPE_LWT_SEG6LOCAL)
	LircMode2             = ProgramType(sys.BPF_PROG_TYPE_LIRC_MODE2)
	SkReuseport           = ProgramType(sys.BPF_PROG_TYPE_SK_REUSEPORT)
	FlowDissector         = ProgramType(sys.BPF_PROG_TYPE_FLOW_DISSECTOR)
	CGroupSysctl          = ProgramType(sys.BPF_PROG_TYPE_CGROUP_SYSCTL)
	RawTracepointWritable = ProgramType(sys.BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE)
	CGroupSockopt         = ProgramType(sys.BPF_PROG_TYPE_CGROUP_SOCKOPT)
	Tracing               = ProgramType(sys.BPF_PROG_TYPE_TRACING)
	StructOps             = ProgramType(sys.BPF_PROG_TYPE_STRUCT_OPS)
	Extension             = ProgramType(sys.BPF_PROG_TYPE_EXT)
	LSM                   = ProgramType(sys.BPF_PROG_TYPE_LSM)
	SkLookup              = ProgramType(sys.BPF_PROG_TYPE_SK_LOOKUP)
	Syscall               = ProgramType(sys.BPF_PROG_TYPE_SYSCALL)
	Netfilter             = ProgramType(sys.BPF_PROG_TYPE_NETFILTER)
)

//go:generate go run golang.org/x/tools/cmd/stringer@latest -tags linux -output attach_string_linux.go -type AttachType -trimprefix Attach

// AttachNone is an alias for AttachCGroupInetIngress for readability reasons.
const AttachNone AttachType = 0

const (
	AttachCGroupInetIngress          = AttachType(sys.BPF_CGROUP_INET_INGRESS)
	AttachCGroupInetEgress           = AttachType(sys.BPF_CGROUP_INET_EGRESS)
	AttachCGroupInetSockCreate       = AttachType(sys.BPF_CGROUP_INET_SOCK_CREATE)
	AttachCGroupSockOps              = AttachType(sys.BPF_CGROUP_SOCK_OPS)
	AttachSkSKBStreamParser          = AttachType(sys.BPF_SK_SKB_STREAM_PARSER)
	AttachSkSKBStreamVerdict         = AttachType(sys.BPF_SK_SKB_STREAM_VERDICT)
	AttachCGroupDevice               = AttachType(sys.BPF_CGROUP_DEVICE)
	AttachSkMsgVerdict               = AttachType(sys.BPF_SK_MSG_VERDICT)
	AttachCGroupInet4Bind            = AttachType(sys.BPF_CGROUP_INET4_BIND)
	AttachCGroupInet6Bind            = AttachType(sys.BPF_CGROUP_INET6_BIND)
	AttachCGroupInet4Connect         = AttachType(sys.BPF_CGROUP_INET4_CONNECT)
	AttachCGroupInet6Connect         = AttachType(sys.BPF_CGROUP_INET6_CONNECT)
	AttachCGroupInet4PostBind        = AttachType(sys.BPF_CGROUP_INET4_POST_BIND)
	AttachCGroupInet6PostBind        = AttachType(sys.BPF_CGROUP_INET6_POST_BIND)
	AttachCGroupUDP4Sendmsg          = AttachType(sys.BPF_CGROUP_UDP4_SENDMSG)
	AttachCGroupUDP6Sendmsg          = AttachType(sys.BPF_CGROUP_UDP6_SENDMSG)
	AttachLircMode2                  = AttachType(sys.BPF_LIRC_MODE2)
	AttachFlowDissector              = AttachType(sys.BPF_FLOW_DISSECTOR)
	AttachCGroupSysctl               = AttachType(sys.BPF_CGROUP_SYSCTL)
	AttachCGroupUDP4Recvmsg          = AttachType(sys.BPF_CGROUP_UDP4_RECVMSG)
	AttachCGroupUDP6Recvmsg          = AttachType(sys.BPF_CGROUP_UDP6_RECVMSG)
	AttachCGroupGetsockopt           = AttachType(sys.BPF_CGROUP_GETSOCKOPT)
	AttachCGroupSetsockopt           = AttachType(sys.BPF_CGROUP_SETSOCKOPT)
	AttachTraceRawTp                 = AttachType(sys.BPF_TRACE_RAW_TP)
	AttachTraceFEntry                = AttachType(sys.BPF_TRACE_FENTRY)
	AttachTraceFExit                 = AttachType(sys.BPF_TRACE_FEXIT)
	AttachModifyReturn               = AttachType(sys.BPF_MODIFY_RETURN)
	AttachLSMMac                     = AttachType(sys.BPF_LSM_MAC)
	AttachTraceIter                  = AttachType(sys.BPF_TRACE_ITER)
	AttachCgroupInet4GetPeername     = AttachType(sys.BPF_CGROUP_INET4_GETPEERNAME)
	AttachCgroupInet6GetPeername     = AttachType(sys.BPF_CGROUP_INET6_GETPEERNAME)
	AttachCgroupInet4GetSockname     = AttachType(sys.BPF_CGROUP_INET4_GETSOCKNAME)
	AttachCgroupInet6GetSockname     = AttachType(sys.BPF_CGROUP_INET6_GETSOCKNAME)
	AttachXDPDevMap                  = AttachType(sys.BPF_XDP_DEVMAP)
	AttachCgroupInetSockRelease      = AttachType(sys.BPF_CGROUP_INET_SOCK_RELEASE)
	AttachXDPCPUMap                  = AttachType(sys.BPF_XDP_CPUMAP)
	AttachSkLookup                   = AttachType(sys.BPF_SK_LOOKUP)
	AttachXDP                        = AttachType(sys.BPF_XDP)
	AttachSkSKBVerdict               = AttachType(sys.BPF_SK_SKB_VERDICT)
	AttachSkReuseportSelect          = AttachType(sys.BPF_SK_REUSEPORT_SELECT)
	AttachSkReuseportSelectOrMigrate = AttachType(sys.BPF_SK_REUSEPORT_SELECT_OR_MIGRATE)
	AttachPerfEvent                  = AttachType(sys.BPF_PERF_EVENT)
	AttachTraceKprobeMulti           = AttachType(sys.BPF_TRACE_KPROBE_MULTI)
	AttachLSMCgroup                  = AttachType(sys.BPF_LSM_CGROUP)
	AttachStructOps                  = AttachType(sys.BPF_STRUCT_OPS)
	AttachNetfilter                  = AttachType(sys.BPF_NETFILTER)
	AttachTCXIngress                 = AttachType(sys.BPF_TCX_INGRESS)
	AttachTCXEgress                  = AttachType(sys.BPF_TCX_EGRESS)
	AttachTraceUprobeMulti           = AttachType(sys.BPF_TRACE_UPROBE_MULTI)
	AttachCgroupUnixConnect          = AttachType(sys.BPF_CGROUP_UNIX_CONNECT)
	AttachCgroupUnixSendmsg          = AttachType(sys.BPF_CGROUP_UNIX_SENDMSG)
	AttachCgroupUnixRecvmsg          = AttachType(sys.BPF_CGROUP_UNIX_RECVMSG)
	AttachCgroupUnixGetpeername      = AttachType(sys.BPF_CGROUP_UNIX_GETPEERNAME)
	AttachCgroupUnixGetsockname      = AttachType(sys.BPF_CGROUP_UNIX_GETSOCKNAME)
	AttachNetkitPrimary              = AttachType(sys.BPF_NETKIT_PRIMARY)
	AttachNetkitPeer                 = AttachType(sys.BPF_NETKIT_PEER)
)
