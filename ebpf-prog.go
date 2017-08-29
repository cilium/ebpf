// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebpf

import "unsafe"

const (
	MaxBPFInstructions = 4096
	StackSize          = 512
	InstructionSize    = 8
	MaxProgramSize     = InstructionSize * MaxBPFInstructions
	LogBufSize         = 65536
)

type OpCode uint8

const (
	// ALU Instructions 64 bit
	ADDIMM  = OpCode(0x07) // add dst, imm   |  dst += imm
	ADDSRC  = OpCode(0x0f) // add dst, src   |  dst += src
	SUBIMM  = OpCode(0x17) // sub dst, imm   |  dst -= imm
	SUBSRC  = OpCode(0x1f) // sub dst, src   |  dst -= src
	MULIMM  = OpCode(0x27) // mul dst, imm   |  dst *= imm
	MULSRC  = OpCode(0x2f) // mul dst, src   |  dst *= src
	DIVIMM  = OpCode(0x37) // div dst, imm   |  dst /= imm
	DIVSRC  = OpCode(0x3f) // div dst, src   |  dst /= src
	ORIMM   = OpCode(0x47) // or dst, imm    |  dst  |= imm
	ORSRC   = OpCode(0x4f) // or dst, src    |  dst  |= src
	ANDIMM  = OpCode(0x57) // and dst, imm   |  dst &= imm
	ANDSRC  = OpCode(0x5f) // and dst, src   |  dst &= src
	LSHIMM  = OpCode(0x67) // lsh dst, imm   |  dst <<= imm
	LSHSRC  = OpCode(0x6f) // lsh dst, src   |  dst <<= src
	RSHIMM  = OpCode(0x77) // rsh dst, imm   |  dst >>= imm (logical)
	RSHSRC  = OpCode(0x7f) // rsh dst, src   |  dst >>= src (logical)
	NEG     = OpCode(0x87) // neg dst        |  dst = -dst
	MODIMM  = OpCode(0x97) // mod dst, imm   |  dst %= imm
	MODSRC  = OpCode(0x9f) // mod dst, src   |  dst %= src
	XORIMM  = OpCode(0xa7) // xor dst, imm   |  dst ^= imm
	XORSRC  = OpCode(0xaf) // xor dst, src   |  dst ^= src
	MOVIMM  = OpCode(0xb7) // mov dst, imm   |  dst = imm
	MOVSRC  = OpCode(0xbf) // mov dst, src   |  dst = src
	ARSHIMM = OpCode(0xc7) // arsh dst, imm  |  dst >>= imm (arithmetic)
	ARSHSRC = OpCode(0xcf) // arsh dst, src  |  dst >>= src (arithmetic)

	// ALU Instructions 32 bit
	// These instructions use only the lower 32 bits of their
	// operands and zero the upper 32 bits of the destination register.
	ADD32IMM = OpCode(0x04) // add32 dst, imm  |  dst += imm
	ADD32SRC = OpCode(0x0c) // add32 dst, src  |  dst += src
	SUB32IMM = OpCode(0x14) // sub32 dst, imm  |  dst -= imm
	SUB32SRC = OpCode(0x1c) // sub32 dst, src  |  dst -= src
	MUL32IMM = OpCode(0x24) // mul32 dst, imm  |  dst *= imm
	MUL32SRC = OpCode(0x2c) // mul32 dst, src  |  dst *= src
	DIV32IMM = OpCode(0x34) // div32 dst, imm  |  dst /= imm
	DIV32SRC = OpCode(0x3c) // div32 dst, src  |  dst /= src
	OR32IMM  = OpCode(0x44) // or32 dst, imm   |  dst |= imm
	OR32SRC  = OpCode(0x4c) // or32 dst, src   |  dst |= src
	AND32IMM = OpCode(0x54) // and32 dst, imm  |  dst &= imm
	AND32SRC = OpCode(0x5c) // and32 dst, src  |  dst &= src
	LSH32IMM = OpCode(0x64) // lsh32 dst, imm  |  dst <<= imm
	LSH32SRC = OpCode(0x6c) // lsh32 dst, src  |  dst <<= src
	RSH32IMM = OpCode(0x74) // rsh32 dst, imm  |  dst >>= imm (logical)
	RSH32SRC = OpCode(0x7c) // rsh32 dst, src  |  dst >>= src (logical)
	NEG32    = OpCode(0x84) // neg32 dst       |  dst = -dst
	MOD32IMM = OpCode(0x94) // mod32 dst, imm  |  dst %= imm
	MOD32SRC = OpCode(0x9c) // mod32 dst, src  |  dst %= src
	XOR32IMM = OpCode(0xa4) // xor32 dst, imm  |  dst ^= imm
	XOR32SRC = OpCode(0xac) // xor32 dst, src  |  dst ^= src
	MOV32IMM = OpCode(0xb4) // mov32 dst, imm  |  dst = imm
	MOV32SRC = OpCode(0xbc) // mov32 dst, src  |  dst = src

	// Byteswap Instructions
	LE16 = OpCode(0xd4) // le16 dst, imm == 16  |  dst = htole16(dst)
	LE32 = OpCode(0xd4) // le32 dst, imm == 32  |  dst = htole32(dst)
	LE64 = OpCode(0xd4) // le64 dst, imm == 64  |  dst = htole64(dst)
	BE16 = OpCode(0xdc) // be16 dst, imm == 16  |  dst = htobe16(dst)
	BE32 = OpCode(0xdc) // be32 dst, imm == 32  |  dst = htobe32(dst)
	BE64 = OpCode(0xdc) // be64 dst, imm == 64  |  dst = htobe64(dst)

	// Memory Instructions
	LDDW    = OpCode(0x18) // lddw dst, imm          |  dst = imm
	LDABSW  = OpCode(0x20) // ldabsw src, dst, imm   |  See kernel documentation
	LDABSH  = OpCode(0x28) // ldabsh src, dst, imm   |  ...
	LDABSB  = OpCode(0x30) // ldabsb src, dst, imm   |  ...
	LDABSDW = OpCode(0x38) // ldabsdw src, dst, imm  |  ...
	LDINDW  = OpCode(0x40) // ldindw src, dst, imm   |  ...
	LDINDH  = OpCode(0x48) // ldindh src, dst, imm   |  ...
	LDINDB  = OpCode(0x50) // ldindb src, dst, imm   |  ...
	LDINDDW = OpCode(0x58) // ldinddw src, dst, imm  |  ...
	LDXW    = OpCode(0x61) // ldxw dst, [src+off]    |  dst = *(uint32_t *) (src + off)
	LDXH    = OpCode(0x69) // ldxh dst, [src+off]    |  dst = *(uint16_t *) (src + off)
	LDXB    = OpCode(0x71) // ldxb dst, [src+off]    |  dst = *(uint8_t *) (src + off)
	LDXDW   = OpCode(0x79) // ldxdw dst, [src+off]   |  dst = *(uint64_t *) (src + off)
	STW     = OpCode(0x62) // stw [dst+off], imm     |  *(uint32_t *) (dst + off) = imm
	STH     = OpCode(0x6a) // sth [dst+off], imm     |  *(uint16_t *) (dst + off) = imm
	STB     = OpCode(0x72) // stb [dst+off], imm     |  *(uint8_t *) (dst + off) = imm
	STDW    = OpCode(0x7a) // stdw [dst+off], imm    |  *(uint64_t *) (dst + off) = imm
	STXW    = OpCode(0x63) // stxw [dst+off], src    |  *(uint32_t *) (dst + off) = src
	STXH    = OpCode(0x6b) // stxh [dst+off], src    |  *(uint16_t *) (dst + off) = src
	STXB    = OpCode(0x73) // stxb [dst+off], src    |  *(uint8_t *) (dst + off) = src
	STXDW   = OpCode(0x7b) // stxdw [dst+off], src   |  *(uint64_t *) (dst + off) = src

	// Branch Instructions
	JA       = OpCode(0x05) // ja +off             |  PC += off
	JEQIMM   = OpCode(0x15) // jeq dst, imm, +off  |  PC += off if dst == imm
	JEQSRC   = OpCode(0x1d) // jeq dst, src, +off  |  PC += off if dst == src
	JGTIMM   = OpCode(0x25) // jgt dst, imm, +off  |  PC += off if dst > imm
	JGTSRC   = OpCode(0x2d) // jgt dst, src, +off  |  PC += off if dst > src
	JGEIMM   = OpCode(0x35) // jge dst, imm, +off  |  PC += off if dst >= imm
	JGESRC   = OpCode(0x3d) // jge dst, src, +off  |  PC += off if dst >= src
	JSETIMM  = OpCode(0x45) // jset dst, imm, +off |  PC += off if dst & imm
	JSETSRC  = OpCode(0x4d) // jset dst, src, +off |  PC += off if dst & src
	JNEIMM   = OpCode(0x55) // jne dst, imm, +off  |  PC += off if dst != imm
	JNESRC   = OpCode(0x5d) // jne dst, src, +off  |  PC += off if dst != src
	JSGTIMM  = OpCode(0x65) // jsgt dst, imm, +off |  PC += off if dst > imm (signed)
	JSGTSRC  = OpCode(0x6d) // jsgt dst, src, +off |  PC += off if dst > src (signed)
	JSGEIMM  = OpCode(0x75) // jsge dst, imm, +off |  PC += off if dst >= imm (signed)
	JSGESRC  = OpCode(0x7d) // jsge dst, src, +off |  PC += off if dst >= src (signed)
	CALL     = OpCode(0x85) // call imm            |  Function call
	TAILCALL = OpCode(0x9d) // tail call           |  Function call
	EXIT     = OpCode(0x95) // exit                |  return r0
)

type Register uint8

const (
	// R0   - return value from in-kernel function, and exit value for eBPF program
	// R1>= - arguments from eBPF program to in-kernel function
	// R6>= - callee saved registers that in-kernel function will preserve
	// R10  - read-only frame pointer to access stack
	REG0 = Register(iota)
	REG1
	REG2
	REG3
	REG4
	REG5
	REG6
	REG7
	REG8
	REG9
	REG10
)

type IMM int32

const (
	// void *map_lookup_elem(&map, &key)
	// Return: Map value or NULL
	MapLookupElement = IMM(iota + 1)
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
	//	int bpf_skb_get_tunnel_key(skb, key, size, flags)
	// *     retrieve or populate tunnel metadata
	// *     @skb: pointer to skb
	// *     @key: pointer to 'struct bpf_tunnel_key'
	// *     @size: size of 'struct bpf_tunnel_key'
	// *     @flags: room for future extensions
	// *     Return: 0 on success or negative error
	SKBGetTunnelKey
	//	int bpf_skb_get_tunnel_key(skb, key, size, flags)
	//	int bpf_skb_set_tunnel_key(skb, key, size, flags)
	// *     retrieve or populate tunnel metadata
	// *     @skb: pointer to skb
	// *     @key: pointer to 'struct bpf_tunnel_key'
	// *     @size: size of 'struct bpf_tunnel_key'
	// *     @flags: room for future extensions
	// *     Return: 0 on success or negative error
	SKBSetTunnelKey
	//	 u64 bpf_perf_event_read(map, flags)
	// *     read perf event counter value
	// *     @map: pointer to perf_event_array map
	// *     @flags: index of event in the map or bitmask flags
	// *     Return: value of perf event counter read or error code
	PerfEventRead
	//	int bpf_redirect(ifindex, flags)
	// *     redirect to another netdev
	// *     @ifindex: ifindex of the net device
	// *     @flags: bit 0 - if set, redirect to ingress instead of egress
	// *             other bits - reserved
	// *     Return: TC_ACT_REDIRECT
	Redirect
	get_route_realm
	perf_event_output
	skb_load_bytes
	get_stackid
	csum_diff
	skb_get_tunnel_opt
	skb_set_tunnel_opt
	skb_change_proto
	skb_change_type
	skb_under_cgroup
	get_hash_recalc
	get_current_task
	probe_write_user
	current_task_under_cgroup
	skb_change_tail
	skb_pull_data
	csum_update
	set_hash_invalid
	get_numa_node_id
	skb_change_head
	xdp_adjust_head
	probe_read_str
	get_socket_cookie
	get_socket_uid
	set_hash
	setsockopt
	skb_adjust_room
)

type bitField uint8

func (r *bitField) SetPart1(v Register) {
	*r = BitField((uint8(*r) & 0xF0) | uint8(v))
}

func (r *bitField) SetPart2(v Register) {
	*r = BitField((uint8(*r) & 0xF) | (uint8(v) << 4))
}

func (r bitField) GetPart1() Register {
	return Register(uint8(r) & 0xF)
}

func (r bitField) GetPart2() Register {
	return Register(uint8(r) >> 4)
}

type BPFInstruction struct {
	OpCode      Opcode
	DstRegister Register
	SrcRegister Register
	Offset      int16
	Constant    int32
}

func (bpi *BPFInstruction) getPointer() unsafe.Pointer {
	var bf BitField
	bf.SetPart1(bpi.DstRegister)
	bf.SetPart2(bpi.SrcRegister)
	return unsafe.Pointer(&(struct {
		opcode    uint8
		registers BitField
		offset    int16
		constant  int32
	}{
		opcode:    bpi.OpCode,
		registers: uint8(bf),
		offset:    bpi.Offset,
		constant:  int32(bpi.Constant),
	}))
}

type BPFProgram struct {
}

func NewBPFProgram(instructions []*BPFInstruction)
