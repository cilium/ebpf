// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebpf

import (
	"fmt"
	"unsafe"
)

const (
	MaxBPFInstructions = 4096
	StackSize          = 512
	InstructionSize    = 8
	LogBufSize         = 65536
)

type OpCode uint8

const (
	// Instruction classes
	Ld = OpCode(iota)
	LdX
	St
	StX
	ALU
	Jmp
	Ret
	Misc

	// ld/ldx fields
	// #define BPF_SIZE(code)  ((code) & 0x18)
	// #define		BPF_W		0x00
	// #define		BPF_H		0x08
	// #define		BPF_B		0x10
	// #define BPF_MODE(code)  ((code) & 0xe0)
	// #define		BPF_IMM		0x00
	// #define		BPF_ABS		0x20
	// #define		BPF_IND		0x40
	// #define		BPF_MEM		0x60
	// #define		BPF_LEN		0x80
	// #define		BPF_MSH		0xa0

	// /* alu/jmp fields */
	// #define BPF_OP(code)    ((code) & 0xf0)
	// #define		BPF_ADD		0x00
	// #define		BPF_SUB		0x10
	// #define		BPF_MUL		0x20
	// #define		BPF_DIV		0x30
	// #define		BPF_OR		0x40
	// #define		BPF_AND		0x50
	// #define		BPF_LSH		0x60
	// #define		BPF_RSH		0x70
	// #define		BPF_NEG		0x80
	// #define		BPF_MOD		0x90
	// #define		BPF_XOR		0xa0

	// #define		BPF_JA		0x00
	// #define		BPF_JEQ		0x10
	// #define		BPF_JGT		0x20
	// #define		BPF_JGE		0x30
	// #define		BPF_JSET        0x40
	// #define BPF_SRC(code)   ((code) & 0x08)
	// #define		BPF_K		0x00
	// #define		BPF_X		0x08
	// ALU Instructions 64 bit
	AddImm    = OpCode(0x07) // add dst, imm   |  dst += imm
	AddSrc    = OpCode(0x0f) // add dst, src   |  dst += src
	XAddStImm = OpCode(0xda) // xadd dst, imm  |  *dst += imm
	XAddStSrc = OpCode(0xdb) // xadd dst, src  |  *dst += src
	SubImm    = OpCode(0x17) // sub dst, imm   |  dst -= imm
	SubSrc    = OpCode(0x1f) // sub dst, src   |  dst -= src
	MulImm    = OpCode(0x27) // mul dst, imm   |  dst *= imm
	MulSrc    = OpCode(0x2f) // mul dst, src   |  dst *= src
	DivImm    = OpCode(0x37) // div dst, imm   |  dst /= imm
	DivSrc    = OpCode(0x3f) // div dst, src   |  dst /= src
	OrImm     = OpCode(0x47) // or dst, imm    |  dst  |= imm
	OrSrc     = OpCode(0x4f) // or dst, src    |  dst  |= src
	AndImm    = OpCode(0x57) // and dst, imm   |  dst &= imm
	AndSrc    = OpCode(0x5f) // and dst, src   |  dst &= src
	LShImm    = OpCode(0x67) // lsh dst, imm   |  dst <<= imm
	LShSrc    = OpCode(0x6f) // lsh dst, src   |  dst <<= src
	RShImm    = OpCode(0x77) // rsh dst, imm   |  dst >>= imm (logical)
	RShSrc    = OpCode(0x7f) // rsh dst, src   |  dst >>= src (logical)
	Neg       = OpCode(0x87) // neg dst        |  dst = -dst
	ModImm    = OpCode(0x97) // mod dst, imm   |  dst %= imm
	ModSrc    = OpCode(0x9f) // mod dst, src   |  dst %= src
	XorImm    = OpCode(0xa7) // xor dst, imm   |  dst ^= imm
	XorSrc    = OpCode(0xaf) // xor dst, src   |  dst ^= src
	MovImm    = OpCode(0xb7) // mov dst, imm   |  dst = imm
	MovSrc    = OpCode(0xbf) // mov dst, src   |  dst = src
	ArShImm   = OpCode(0xc7) // arsh dst, imm  |  dst >>= imm (arithmetic)
	ArShSrc   = OpCode(0xcf) // arsh dst, src  |  dst >>= src (arithmetic)

	// ALU Instructions 32 bit
	// These instructions use only the lower 32 bits of their
	// operands and zero the upper 32 bits of the destination register.
	Add32Imm = OpCode(0x04) // add32 dst, imm  |  dst += imm
	Add32Src = OpCode(0x0c) // add32 dst, src  |  dst += src
	Sub32Imm = OpCode(0x14) // sub32 dst, imm  |  dst -= imm
	Sub32Src = OpCode(0x1c) // sub32 dst, src  |  dst -= src
	Mul32Imm = OpCode(0x24) // mul32 dst, imm  |  dst *= imm
	Mul32Src = OpCode(0x2c) // mul32 dst, src  |  dst *= src
	Div32Imm = OpCode(0x34) // div32 dst, imm  |  dst /= imm
	Div32Src = OpCode(0x3c) // div32 dst, src  |  dst /= src
	Or32Imm  = OpCode(0x44) // or32 dst, imm   |  dst |= imm
	Or32Src  = OpCode(0x4c) // or32 dst, src   |  dst |= src
	And32Imm = OpCode(0x54) // and32 dst, imm  |  dst &= imm
	And32Src = OpCode(0x5c) // and32 dst, src  |  dst &= src
	LSh32Imm = OpCode(0x64) // lsh32 dst, imm  |  dst <<= imm
	LSh32Src = OpCode(0x6c) // lsh32 dst, src  |  dst <<= src
	RSh32Imm = OpCode(0x74) // rsh32 dst, imm  |  dst >>= imm (logical)
	RSh32Src = OpCode(0x7c) // rsh32 dst, src  |  dst >>= src (logical)
	Neg32    = OpCode(0x84) // neg32 dst       |  dst = -dst
	Mod32Imm = OpCode(0x94) // mod32 dst, imm  |  dst %= imm
	Mod32Src = OpCode(0x9c) // mod32 dst, src  |  dst %= src
	Xor32Imm = OpCode(0xa4) // xor32 dst, imm  |  dst ^= imm
	Xor32Src = OpCode(0xac) // xor32 dst, src  |  dst ^= src
	Mov32Imm = OpCode(0xb4) // mov32 dst, imm  |  dst = imm
	Mov32Src = OpCode(0xbc) // mov32 dst, src  |  dst = src

	// Byteswap Instructions
	LE16 = OpCode(0xd4) // le16 dst, imm == 16  |  dst = htole16(dst)
	LE32 = OpCode(0xd4) // le32 dst, imm == 32  |  dst = htole32(dst)
	LE64 = OpCode(0xd4) // le64 dst, imm == 64  |  dst = htole64(dst)
	BE16 = OpCode(0xdc) // be16 dst, imm == 16  |  dst = htobe16(dst)
	BE32 = OpCode(0xdc) // be32 dst, imm == 32  |  dst = htobe32(dst)
	BE64 = OpCode(0xdc) // be64 dst, imm == 64  |  dst = htobe64(dst)

	// Memory Instructions
	// the variable "mem", means skb->data in the context of
	// a socket prog, but in other context means other things.
	LdDW    = OpCode(0x18) // lddw (src), dst, imm   |  dst = *imm
	LdAbsB  = OpCode(0x30) // ldabsb imm             |  r0 = *(uint8_t *) (mem + imm)
	LdAbsH  = OpCode(0x28) // ldabsh imm             |  r0 = *(uint16_t *) (mem + imm)
	LdAbsW  = OpCode(0x20) // ldabsw imm             |  r0 = *(uint32_t *) (mem + imm)
	LdAbsDW = OpCode(0x38) // ldabsdw imm            |  r0 = *(uint64_t *) (mem + imm)
	LdIndW  = OpCode(0x40) // ldindw src, dst, imm   |  ...
	LdIndH  = OpCode(0x48) // ldindh src, dst, imm   |  ...
	LdIndB  = OpCode(0x50) // ldindb src, dst, imm   |  ...
	LdIndDW = OpCode(0x58) // ldinddw src, dst, imm  |  ...
	LdXW    = OpCode(0x61) // ldxw dst, [src+off]    |  dst = *(uint32_t *) (src + off)
	LdXH    = OpCode(0x69) // ldxh dst, [src+off]    |  dst = *(uint16_t *) (src + off)
	LdXB    = OpCode(0x71) // ldxb dst, [src+off]    |  dst = *(uint8_t *) (src + off)
	LdXDW   = OpCode(0x79) // ldxdw dst, [src+off]   |  dst = *(uint64_t *) (src + off)
	StB     = OpCode(0x72) // stb [dst+off], imm     |  *(uint8_t *) (dst + off) = imm
	StH     = OpCode(0x6a) // sth [dst+off], imm     |  *(uint16_t *) (dst + off) = imm
	StW     = OpCode(0x62) // stw [dst+off], imm     |  *(uint32_t *) (dst + off) = imm
	StDW    = OpCode(0x7a) // stdw [dst+off], imm    |  *(uint64_t *) (dst + off) = imm
	StXB    = OpCode(0x73) // stxb [dst+off], src    |  *(uint8_t *) (dst + off) = src
	StXH    = OpCode(0x6b) // stxh [dst+off], src    |  *(uint16_t *) (dst + off) = src
	StXW    = OpCode(0x63) // stxw [dst+off], src    |  *(uint32_t *) (dst + off) = src
	StXDW   = OpCode(0x7b) // stxdw [dst+off], src   |  *(uint64_t *) (dst + off) = src

	// Branch Instructions
	JA      = OpCode(0x05) // ja +off             |  PC += off
	JEqImm  = OpCode(0x15) // jeq dst, imm, +off  |  PC += off if dst == imm
	JEqSrc  = OpCode(0x1d) // jeq dst, src, +off  |  PC += off if dst == src
	JGtImm  = OpCode(0x25) // jgt dst, imm, +off  |  PC += off if dst > imm
	JGtSrc  = OpCode(0x2d) // jgt dst, src, +off  |  PC += off if dst > src
	JGeImm  = OpCode(0x35) // jge dst, imm, +off  |  PC += off if dst >= imm
	JGeSrc  = OpCode(0x3d) // jge dst, src, +off  |  PC += off if dst >= src
	JSETImm = OpCode(0x45) // jset dst, imm, +off |  PC += off if dst & imm
	JSETSrc = OpCode(0x4d) // jset dst, src, +off |  PC += off if dst & src
	JNEImm  = OpCode(0x55) // jne dst, imm, +off  |  PC += off if dst != imm
	JNESrc  = OpCode(0x5d) // jne dst, src, +off  |  PC += off if dst != src
	JSGtImm = OpCode(0x65) // jsgt dst, imm, +off |  PC += off if dst > imm (signed)
	JSGtSrc = OpCode(0x6d) // jsgt dst, src, +off |  PC += off if dst > src (signed)
	JSGeImm = OpCode(0x75) // jsge dst, imm, +off |  PC += off if dst >= imm (signed)
	JSGeSrc = OpCode(0x7d) // jsge dst, src, +off |  PC += off if dst >= src (signed)
	Call    = OpCode(0x85) // call imm            |  Function call
	Exit    = OpCode(0x95) // exit                |  return r0
)

type Register uint8

const (
	// R0   - return value from in-kernel function, and exit value for eBPF program
	// R1>= - arguments from eBPF program to in-kernel function
	// R6>= - callee saved registers that in-kernel function will preserve
	// R10  - read-only frame pointer to access stack
	Reg0 = Register(iota)
	Reg1
	Reg2
	Reg3
	Reg4
	Reg5
	Reg6
	Reg7
	Reg8
	Reg9
	Reg10
)

const (
	// void *map_lookup_elem(&map, &key)
	// Return: Map value or NULL
	MapLookupElement = int32(iota + 1)
	// int map_update_elem(&map, &key, &value, flags)
	// Return: 0 on success or negative error
	MapUpdateElement
	// int map_delete_elem(&map, &key)
	// Return: 0 on success or negative error
	MapDeleteElement
	// int bpf_probe_read(void *dst, int size, void *src)
	// Return: 0 on success or negative error
	ProbeRead
	// u64 bpf_ktime_get_ns(void)
	// Return: current ktime
	KtimeGetNS
	// int bpf_trace_printk(const char *fmt, int fmt_size, ...)
	// Return: length of buffer written or negative error
	TracePrintk
	// u32 prandom_u32(void)
	// Return: random value
	GetPRandomu32
	// u32 raw_smp_processor_id(void)
	// Return: SMP processor ID
	GetSMPProcessorID
	// skb_store_bytes(skb, offset, from, len, flags)
	// store bytes into packet
	// @skb: pointer to skb
	// @offset: offset within packet from skb->mac_header
	// @from: pointer where to copy bytes from
	// @len: number of bytes to store into packet
	// @flags: bit 0 - if true, recompute skb->csum
	//         other bits - reserved
	// Return: 0 on success
	SKBStoreBytes
	// l3_csum_replace(skb, offset, from, to, flags)
	// recompute IP checksum
	// @skb: pointer to skb
	// @offset: offset within packet where IP checksum is located
	// @from: old value of header field
	// @to: new value of header field
	// @flags: bits 0-3 - size of header field
	//         other bits - reserved
	// Return: 0 on success
	CSUMReplaceL3
	// l4_csum_replace(skb, offset, from, to, flags)
	// recompute TCP/UDP checksum
	// @skb: pointer to skb
	// @offset: offset within packet where TCP/UDP checksum is located
	// @from: old value of header field
	// @to: new value of header field
	// @flags: bits 0-3 - size of header field
	//         bit 4 - is pseudo header
	//         other bits - reserved
	// Return: 0 on success
	CSUMReplaceL4
	// int bpf_tail_call(ctx, prog_array_map, index)
	// jump into another BPF program
	// @ctx: context pointer passed to next program
	// @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
	// @index: index inside array that selects specific program to run
	// Return: 0 on success or negative error
	TailCall
	// int bpf_clone_redirect(skb, ifindex, flags)
	// redirect to another netdev
	// @skb: pointer to skb
	// @ifindex: ifindex of the net device
	// @flags: bit 0 - if set, redirect to ingress instead of egress
	//         other bits - reserved
	// Return: 0 on success or negative error
	CloneRedirect
	// u64 bpf_get_current_pid_tgid(void)
	// Return: current->tgid << 32 | current->pid
	GetCurrentPidTGid
	// u64 bpf_get_current_uid_gid(void)
	// Return: current_gid << 32 | current_uid
	GetCurrentUidGid
	// int bpf_get_current_comm(char *buf, int size_of_buf) - stores current->comm into buf
	// Return: 0 on success or negative error
	GetCurrentComm
	// u32 bpf_get_cgroup_classid(skb)
	// retrieve a proc's classid
	// @skb: pointer to skb
	// Return: classid if != 0
	GetCGroupClassId
	// int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
	// Return: 0 on success or negative error
	SKBVlanPush
	// int bpf_skb_vlan_pop(skb)
	// Return: 0 on success or negative error
	SKBVlanPop
	// int bpf_skb_get_tunnel_key(skb, key, size, flags)
	// retrieve or populate tunnel metadata
	// @skb: pointer to skb
	// @key: pointer to 'struct bpf_tunnel_key'
	// @size: size of 'struct bpf_tunnel_key'
	// @flags: room for future extensions
	// Return: 0 on success or negative error
	SKBGetTunnelKey
	// int bpf_skb_set_tunnel_key(skb, key, size, flags)
	// retrieve or populate tunnel metadata
	// @skb: pointer to skb
	// @key: pointer to 'struct bpf_tunnel_key'
	// @size: size of 'struct bpf_tunnel_key'
	// @flags: room for future extensions
	// Return: 0 on success or negative error
	SKBSetTunnelKey
	//  u64 bpf_perf_event_read(map, flags)
	// read perf event counter value
	// @map: pointer to perf_event_array map
	// @flags: index of event in the map or bitmask flags
	// Return: value of perf event counter read or error code
	PerfEventRead
	// int bpf_redirect(ifindex, flags)
	// redirect to another netdev
	// @ifindex: ifindex of the net device
	// @flags: bit 0 - if set, redirect to ingress instead of egress
	//         other bits - reserved
	// Return: TC_ACT_REDIRECT
	Redirect
	// u32 bpf_get_route_realm(skb)
	// retrieve a dst's tclassid
	// @skb: pointer to skb
	// Return: realm if != 0
	GetRouteRealm
	// int bpf_perf_event_output(ctx, map, flags, data, size)
	// output perf raw sample
	// @ctx: struct pt_regs*
	// @map: pointer to perf_event_array map
	// @flags: index of event in the map or bitmask flags
	// @data: data on stack to be output as raw data
	// @size: size of data
	// Return: 0 on success or negative error
	PerfEventOutput
	// int bpf_get_stackid(ctx, map, flags)
	// walk user or kernel stack and return id
	// @ctx: struct pt_regs*
	// @map: pointer to stack_trace map
	// @flags: bits 0-7 - numer of stack frames to skip
	//         bit 8 - collect user stack instead of kernel
	//         bit 9 - compare stacks by hash only
	//         bit 10 - if two different stacks hash into the same stackid
	//                  discard old
	//         other bits - reserved
	// Return: >= 0 stackid on success or negative error
	GetStackID
	// s64 bpf_csum_diff(from, from_size, to, to_size, seed)
	// calculate csum diff
	// @from: raw from buffer
	// @from_size: length of from buffer
	// @to: raw to buffer
	// @to_size: length of to buffer
	// @seed: optional seed
	// Return: csum result or negative error code
	CsumDiff
	// int bpf_skb_get_tunnel_opt(skb, opt, size)
	// retrieve tunnel options metadata
	// @skb: pointer to skb
	// @opt: pointer to raw tunnel option data
	// @size: size of @opt
	// Return: option size
	SKBGetTunnelOpt
	// int bpf_skb_set_tunnel_opt(skb, opt, size)
	// populate tunnel options metadata
	// @skb: pointer to skb
	// @opt: pointer to raw tunnel option data
	// @size: size of @opt
	// Return: 0 on success or negative error
	SKBSetTunnelOpt
	// int bpf_skb_change_proto(skb, proto, flags)
	// Change protocol of the skb. Currently supported is v4 -> v6,
	// v6 -> v4 transitions. The helper will also resize the skb. eBPF
	// program is expected to fill the new headers via skb_store_bytes
	// and lX_csum_replace.
	// @skb: pointer to skb
	// @proto: new skb->protocol type
	// @flags: reserved
	// Return: 0 on success or negative error
	SKBchangeProto
	// int bpf_skb_change_type(skb, type)
	// Change packet type of skb.
	// @skb: pointer to skb
	// @type: new skb->pkt_type type
	// Return: 0 on success or negative error
	SKBChangeType
	// int bpf_skb_under_cgroup(skb, map, index)
	// Check cgroup2 membership of skb
	// @skb: pointer to skb
	// @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
	// @index: index of the cgroup in the bpf_map
	// Return:
	//   == 0 skb failed the cgroup2 descendant test
	//   == 1 skb succeeded the cgroup2 descendant test
	//    < 0 error
	SKBUnderCGroup
	// u32 bpf_get_hash_recalc(skb)
	// Retrieve and possibly recalculate skb->hash.
	// @skb: pointer to skb
	// Return: hash
	GetHashRecalc
	// u64 bpf_get_current_task(void)
	// Returns current task_struct
	// Return: current
	GetCurrentTask
	// int bpf_probe_write_user(void *dst, void *src, int len)
	// safely attempt to write to a location
	// @dst: destination address in userspace
	// @src: source address on stack
	// @len: number of bytes to copy
	// Return: 0 on success or negative error
	ProbeWriteUser
	// int bpf_current_task_under_cgroup(map, index)
	// Check cgroup2 membership of current task
	// @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
	// @index: index of the cgroup in the bpf_map
	// Return:
	//   == 0 current failed the cgroup2 descendant test
	//   == 1 current succeeded the cgroup2 descendant test
	//    < 0 error
	CurrentTaskUnderCGroup
	// int bpf_skb_change_tail(skb, len, flags)
	// The helper will resize the skb to the given new size, to be used f.e.
	// with control messages.
	// @skb: pointer to skb
	// @len: new skb length
	// @flags: reserved
	// Return: 0 on success or negative error
	SKBChangeTail
	// int bpf_skb_pull_data(skb, len)
	// The helper will pull in non-linear data in case the skb is non-linear
	// and not all of len are part of the linear section. Only needed for
	// read/write with direct packet access.
	// @skb: pointer to skb
	// @Len: len to make read/writeable
	// Return: 0 on success or negative error
	SKBPullData
	// s64 bpf_csum_update(skb, csum)
	// Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
	// @skb: pointer to skb
	// @csum: csum to add
	// Return: csum on success or negative error
	CSUMUpdate
	// void bpf_set_hash_invalid(skb)
	// Invalidate current skb->hash.
	// @skb: pointer to skb
	SetHashInvalid
	// int bpf_get_numa_node_id()
	// Return: Id of current NUMA node.
	GetNUMANodeID
	// int bpf_skb_change_head()
	// Grows headroom of skb and adjusts MAC header offset accordingly.
	// Will extends/reallocae as required automatically.
	// May change skb data pointer and will thus invalidate any check
	// performed for direct packet access.
	// @skb: pointer to skb
	// @len: length of header to be pushed in front
	// @flags: Flags (unused for now)
	// Return: 0 on success or negative error
	SKBChangeHead
	// int bpf_xdp_adjust_head(xdp_md, delta)
	// Adjust the xdp_md.data by delta
	// @xdp_md: pointer to xdp_md
	// @delta: An positive/negative integer to be added to xdp_md.data
	// Return: 0 on success or negative on error
	XDPAdjustHead
	// int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
	// Copy a NUL terminated string from unsafe address. In case the string
	// length is smaller than size, the target is not padded with further NUL
	// bytes. In case the string length is larger than size, just count-1
	// bytes are copied and the last byte is set to NUL.
	// @dst: destination address
	// @size: maximum number of bytes to copy, including the trailing NUL
	// @unsafe_ptr: unsafe address
	// Return:
	//   > 0 length of the string including the trailing NUL on success
	//   < 0 error
	ProbeReadStr
	// u64 bpf_get_socket_cookie(skb)
	// Get the cookie for the socket stored inside sk_buff.
	// @skb: pointer to skb
	// Return: 8 Bytes non-decreasing number on success or 0 if the socket
	// field is missing inside sk_buff
	GetSocketCookie
	// u32 bpf_get_socket_uid(skb)
	// Get the owner uid of the socket stored inside sk_buff.
	// @skb: pointer to skb
	// Return: uid of the socket owner on success or overflowuid if failed.
	GetSocketUID
	// u32 bpf_set_hash(skb, hash)
	// Set full skb->hash.
	// @skb: pointer to skb
	// @hash: hash to set
	SetHash
	// int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
	// Calls setsockopt. Not all opts are available, only those with
	// integer optvals plus TCP_CONGESTION.
	// Supported levels: SOL_SOCKET and IPROTO_TCP
	// @bpf_socket: pointer to bpf_socket
	// @level: SOL_SOCKET or IPROTO_TCP
	// @optname: option name
	// @optval: pointer to option value
	// @optlen: length of optval in byes
	// Return: 0 or negative error
	SetSockOpt
	// int bpf_skb_adjust_room(skb, len_diff, mode, flags)
	// Grow or shrink room in sk_buff.
	// @skb: pointer to skb
	// @len_diff: (signed) amount of room to grow/shrink
	// @mode: operation mode (enum bpf_adj_room_mode)
	// @flags: reserved for future use
	// Return: 0 on success or negative error code
	SKBAdjustRoom
)

// All flags used by eBPF helper functions
const (
	// BPF_FUNC_skb_store_bytes flags.
	RecomputeCSUM   = uint64(1)
	FInvalidateHash = uint64(1 << 1)

	// BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
	// First 4 bits are for passing the header field size.
	FHdrFieldMask = uint64(0xF)

	// BPF_FUNC_l4_csum_replace flags.
	FPseudoHdr    = uint64(1 << 4)
	FMarkMangled0 = uint64(1 << 5)
	FMakrEnforce  = uint64(1 << 6)

	// BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags.
	FIngress = uint64(1)

	// BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags.
	FTunInfoIPV6 = uint(1)

	// BPF_FUNC_get_stackid flags
	FSkipFieldMask = uint64(0xff)

	FUserStack    = uint64(1 << 8)
	FFastStackCMP = uint64(1 << 9)
	FReuseStackID = uint64(1 << 10)

	// BPF_FUNC_skb_set_tunnel_key flags.
	FZeroCSUMTX   = uint64(1 << 1)
	FDontFragment = uint64(1 << 2)

	// BPF_FUNC_perf_event_output and BPF_FUNC_perf_event_read flags.
	FIndexMask  = uint64(0xffffffff)
	FCurrentCPU = FIndexMask

	// BPF_FUNC_perf_event_output for sk_buff input context.
	FCtxLenMask = uint64(0xfffff << 32)

	// Mode for BPF_FUNC_skb_adjust_room helper.
	AdjRoomNet = 0
)

type ProgType uint32

const (
	ProgTypeSocketFilter = ProgType(iota + 1)
	ProgTypeKprobe
	ProgTypeSchedCLS
	ProgTypeSchedACT
	ProgTypeTracePoint
	ProgTypeXDP
	ProgTypePerfEvent
	ProgTypeCGroupSKB
	ProgTypeCGroupSock
	ProgTypeLWTIn
	ProgTypeLWTOut
	ProgTypeLWTXmit
	ProgTypeSockOps
)

type SKBuff struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VLANPresent    uint32
	VLANTCI        uint32
	VLANProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TCIndex        uint32
	CB             [5]uint32
	Hash           uint32
	TCClassID      uint32
	Data           uint32
	DataEnd        uint32
	NAPIID         uint32
}

type bitField uint8

func (r *bitField) SetPart1(v Register) {
	*r = bitField((uint8(*r) & 0xF0) | uint8(v))
}

func (r *bitField) SetPart2(v Register) {
	*r = bitField((uint8(*r) & 0xF) | (uint8(v) << 4))
}

func (r bitField) GetPart1() Register {
	return Register(uint8(r) & 0xF)
}

func (r bitField) GetPart2() Register {
	return Register(uint8(r) >> 4)
}

type BPFInstruction struct {
	OpCode      OpCode
	DstRegister Register
	SrcRegister Register
	Offset      int16
	Constant    int32
}

type bpfInstruction struct {
	opcode    uint8
	registers uint8
	offset    int16
	constant  int32
}

func BPFIOp(opCode OpCode) *BPFInstruction {
	return &BPFInstruction{
		OpCode: opCode,
	}
}

func BPFIDst(opCode OpCode, dst Register) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
	}
}

func BPFIImm(opCode OpCode, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:   opCode,
		Constant: imm,
	}
}

func BPFIDstImm(opCode OpCode, dst Register, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		Constant:    imm,
	}
}

func BPFIDstSrc(opCode OpCode, dst, src Register) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
	}
}

func BPFIDstOffImm(opCode OpCode, dst Register, off int16, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		Offset:      off,
		Constant:    imm,
	}
}

func BPFIDstOffSrc(opCode OpCode, dst, src Register, off int16) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Offset:      off,
	}
}

func BPFIDstOffImmSrc(opCode OpCode, dst, src Register, off int16, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Offset:      off,
		Constant:    imm,
	}
}

func (bpi *BPFInstruction) getCStruct() bpfInstruction {
	var bf bitField
	bf.SetPart1(bpi.DstRegister)
	bf.SetPart2(bpi.SrcRegister)
	return bpfInstruction{
		opcode:    uint8(bpi.OpCode),
		registers: uint8(bf),
		offset:    bpi.Offset,
		constant:  bpi.Constant,
	}
}

type BPFProgram struct {
	fd   int
	logs []byte
}

func NewBPFProgram(progType ProgType, instructions []*BPFInstruction, license string) (*BPFProgram, error) {
	insCount := uint32(len(instructions))
	if insCount > MaxBPFInstructions {
		return nil, fmt.Errorf("max instructions, %s, exceeded", MaxBPFInstructions)
	}
	cInstructions := make([]bpfInstruction, insCount)
	for i, ins := range instructions {
		cInstructions[i] = ins.getCStruct()
	}
	bpfP := new(BPFProgram)
	lic := []byte(license)
	bpfP.logs = make([]byte, LogBufSize)
	fd, e := bpfCall(_BPF_PROG_LOAD, unsafe.Pointer((&struct {
		progType     uint32
		insCount     uint32
		instructions uint64
		license      uint64
		logLevel     uint32
		logSize      uint32
		logBuf       uint64
		kernVersion  uint32
		padding      uint32
	}{
		progType:     uint32(progType),
		insCount:     insCount,
		instructions: uint64(uintptr(unsafe.Pointer(&cInstructions[0]))),
		license:      uint64(uintptr(unsafe.Pointer(&lic[0]))),
		logLevel:     1,
		logSize:      LogBufSize,
		logBuf:       uint64(uintptr(unsafe.Pointer(&bpfP.logs[0]))),
	})), 48)
	if e != 0 {
		logs := bpfP.GetLogs()
		if len(logs) > 0 {
			return nil, fmt.Errorf("%s: %s", errnoErr(e), logs)
		}
		return bpfP, errnoErr(e)
	}
	bpfP.fd = int(fd)
	return bpfP, nil
}

func (bpf *BPFProgram) GetLogs() string {
	if bpf.logs == nil {
		return ""
	}
	return string(bpf.logs)
}

func (bfp *BPFProgram) GetFd() int {
	return bfp.fd
}
