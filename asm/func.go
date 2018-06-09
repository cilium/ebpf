package asm

//go:generate stringer -output func_string.go -type=BuiltinFunc

// BuiltinFunc is a built-in eBPF function.
type BuiltinFunc int32

// eBPF built-in functions
const (
	// MapLookupElement - void *map_lookup_elem(&map, &key)
	// Return: Map value or NULL
	MapLookupElement BuiltinFunc = iota + 1
	// MapUpdateElement - int map_update_elem(&map, &key, &value, flags)
	// Return: 0 on success or negative error
	MapUpdateElement
	// MapDeleteElement - int map_delete_elem(&map, &key)
	// Return: 0 on success or negative error
	MapDeleteElement
	// ProbeRead - int bpf_probe_read(void *dst, int size, void *src)
	// Return: 0 on success or negative error
	ProbeRead
	// KtimeGetNS - u64 bpf_ktime_get_ns(void)
	// Return: current ktime
	KtimeGetNS
	// TracePrintk - int bpf_trace_printk(const char *fmt, int fmt_size, ...)
	// Return: length of buffer written or negative error
	TracePrintk
	// GetPRandomu32 - u32 prandom_u32(void)
	// Return: random value
	GetPRandomu32
	// GetSMPProcessorID - u32 raw_smp_processor_id(void)
	// Return: SMP processor ID
	GetSMPProcessorID
	// SKBStoreBytes - skb_store_bytes(skb, offset, from, len, flags)
	// store bytes into packet
	// @skb: pointer to skb
	// @offset: offset within packet from skb->mac_header
	// @from: pointer where to copy bytes from
	// @len: number of bytes to store into packet
	// @flags: bit 0 - if true, recompute skb->csum
	//         other bits - reserved
	// Return: 0 on success
	SKBStoreBytes
	// CSUMReplaceL3 - l3_csum_replace(skb, offset, from, to, flags)
	// recompute IP checksum
	// @skb: pointer to skb
	// @offset: offset within packet where IP checksum is located
	// @from: old value of header field
	// @to: new value of header field
	// @flags: bits 0-3 - size of header field
	//         other bits - reserved
	// Return: 0 on success
	CSUMReplaceL3
	// CSUMReplaceL4 - l4_csum_replace(skb, offset, from, to, flags)
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
	// TailCall - int bpf_tail_call(ctx, prog_array_map, index)
	// jump into another BPF program
	// @ctx: context pointer passed to next program
	// @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
	// @index: index inside array that selects specific program to run
	// Return: 0 on success or negative error
	TailCall
	// CloneRedirect - int bpf_clone_redirect(skb, ifindex, flags)
	// redirect to another netdev
	// @skb: pointer to skb
	// @ifindex: ifindex of the net device
	// @flags: bit 0 - if set, redirect to ingress instead of egress
	//         other bits - reserved
	// Return: 0 on success or negative error
	CloneRedirect
	// GetCurrentPIDTGID - u64 bpf_get_current_pid_tgid(void)
	// Return: current->tgid << 32 | current->pid
	GetCurrentPIDTGID
	// GetCurrentUIDGID - u64 bpf_get_current_uid_gid(void)
	// Return: current_gid << 32 | current_uid
	GetCurrentUIDGID
	// GetCurrentComm - int bpf_get_current_comm(char *buf, int size_of_buf) - stores current->comm into buf
	// Return: 0 on success or negative error
	GetCurrentComm
	// GetCGroupClassID - u32 bpf_get_cgroup_classid(skb)
	// retrieve a proc's classid
	// @skb: pointer to skb
	// Return: classid if != 0
	GetCGroupClassID
	// SKBVlanPush - int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
	// Return: 0 on success or negative error
	SKBVlanPush
	// SKBVlanPop - int bpf_skb_vlan_pop(skb)
	// Return: 0 on success or negative error
	SKBVlanPop
	// SKBGetTunnelKey - int bpf_skb_get_tunnel_key(skb, key, size, flags)
	// retrieve or populate tunnel metadata
	// @skb: pointer to skb
	// @key: pointer to 'struct bpf_tunnel_key'
	// @size: size of 'struct bpf_tunnel_key'
	// @flags: room for future extensions
	// Return: 0 on success or negative error
	SKBGetTunnelKey
	// SKBSetTunnelKey - int bpf_skb_set_tunnel_key(skb, key, size, flags)
	// retrieve or populate tunnel metadata
	// @skb: pointer to skb
	// @key: pointer to 'struct bpf_tunnel_key'
	// @size: size of 'struct bpf_tunnel_key'
	// @flags: room for future extensions
	// Return: 0 on success or negative error
	SKBSetTunnelKey
	// PerfEventRead - u64 bpf_perf_event_read(map, flags)
	// read perf event counter value
	// @map: pointer to perf_event_array map
	// @flags: index of event in the map or bitmask flags
	// Return: value of perf event counter read or error code
	PerfEventRead
	// Redirect - int bpf_redirect(ifindex, flags)
	// redirect to another netdev
	// @ifindex: ifindex of the net device
	// @flags: bit 0 - if set, redirect to ingress instead of egress
	//         other bits - reserved
	// Return: TC_ACT_REDIRECT
	Redirect
	// GetRouteRealm - u32 bpf_get_route_realm(skb)
	// retrieve a dst's tclassid
	// @skb: pointer to skb
	// Return: realm if != 0
	GetRouteRealm
	// PerfEventOutput - int bpf_perf_event_output(ctx, map, flags, data, size)
	// output perf raw sample
	// @ctx: struct pt_regs*
	// @map: pointer to perf_event_array map
	// @flags: index of event in the map or bitmask flags
	// @data: data on stack to be output as raw data
	// @size: size of data
	// Return: 0 on success or negative error
	PerfEventOutput
	// GetStackID - int bpf_get_stackid(ctx, map, flags)
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
	// CsumDiff - s64 bpf_csum_diff(from, from_size, to, to_size, seed)
	// calculate csum diff
	// @from: raw from buffer
	// @from_size: length of from buffer
	// @to: raw to buffer
	// @to_size: length of to buffer
	// @seed: optional seed
	// Return: csum result or negative error code
	CsumDiff
	// SKBGetTunnelOpt - int bpf_skb_get_tunnel_opt(skb, opt, size)
	// retrieve tunnel options metadata
	// @skb: pointer to skb
	// @opt: pointer to raw tunnel option data
	// @size: size of @opt
	// Return: option size
	SKBGetTunnelOpt
	// SKBSetTunnelOpt - int bpf_skb_set_tunnel_opt(skb, opt, size)
	// populate tunnel options metadata
	// @skb: pointer to skb
	// @opt: pointer to raw tunnel option data
	// @size: size of @opt
	// Return: 0 on success or negative error
	SKBSetTunnelOpt
	// SKBChangeProto - int bpf_skb_change_proto(skb, proto, flags)
	// Change protocol of the skb. Currently supported is v4 -> v6,
	// v6 -> v4 transitions. The helper will also resize the skb. eBPF
	// program is expected to fill the new headers via skb_store_bytes
	// and lX_csum_replace.
	// @skb: pointer to skb
	// @proto: new skb->protocol type
	// @flags: reserved
	// Return: 0 on success or negative error
	SKBChangeProto
	// SKBChangeType - int bpf_skb_change_type(skb, type)
	// Change packet type of skb.
	// @skb: pointer to skb
	// @type: new skb->pkt_type type
	// Return: 0 on success or negative error
	SKBChangeType
	// SKBUnderCGroup - int bpf_skb_under_cgroup(skb, map, index)
	// Check cgroup2 membership of skb
	// @skb: pointer to skb
	// @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
	// @index: index of the cgroup in the bpf_map
	// Return:
	//   == 0 skb failed the cgroup2 descendant test
	//   == 1 skb succeeded the cgroup2 descendant test
	//    < 0 error
	SKBUnderCGroup
	// GetHashRecalc - u32 bpf_get_hash_recalc(skb)
	// Retrieve and possibly recalculate skb->hash.
	// @skb: pointer to skb
	// Return: hash
	GetHashRecalc
	// GetCurrentTask - u64 bpf_get_current_task(void)
	// Returns current task_struct
	// Return: current
	GetCurrentTask
	// ProbeWriteUser - int bpf_probe_write_user(void *dst, void *src, int len)
	// safely attempt to write to a location
	// @dst: destination address in userspace
	// @src: source address on stack
	// @len: number of bytes to copy
	// Return: 0 on success or negative error
	ProbeWriteUser
	// CurrentTaskUnderCGroup - int bpf_current_task_under_cgroup(map, index)
	// Check cgroup2 membership of current task
	// @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
	// @index: index of the cgroup in the bpf_map
	// Return:
	//   == 0 current failed the cgroup2 descendant test
	//   == 1 current succeeded the cgroup2 descendant test
	//    < 0 error
	CurrentTaskUnderCGroup
	// SKBChangeTail - int bpf_skb_change_tail(skb, len, flags)
	// The helper will resize the skb to the given new size, to be used f.e.
	// with control messages.
	// @skb: pointer to skb
	// @len: new skb length
	// @flags: reserved
	// Return: 0 on success or negative error
	SKBChangeTail
	// SKBPullData - int bpf_skb_pull_data(skb, len)
	// The helper will pull in non-linear data in case the skb is non-linear
	// and not all of len are part of the linear section. Only needed for
	// read/write with direct packet access.
	// @skb: pointer to skb
	// @Len: len to make read/writeable
	// Return: 0 on success or negative error
	SKBPullData
	// CSUMUpdate - s64 bpf_csum_update(skb, csum)
	// Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
	// @skb: pointer to skb
	// @csum: csum to add
	// Return: csum on success or negative error
	CSUMUpdate
	// SetHashInvalid - void bpf_set_hash_invalid(skb)
	// Invalidate current skb->hash.
	// @skb: pointer to skb
	SetHashInvalid
	// GetNUMANodeID - int bpf_get_numa_node_id()
	// Return: Id of current NUMA node.
	GetNUMANodeID
	// SKBChangeHead - int bpf_skb_change_head()
	// Grows headroom of skb and adjusts MAC header offset accordingly.
	// Will extends/reallocae as required automatically.
	// May change skb data pointer and will thus invalidate any check
	// performed for direct packet access.
	// @skb: pointer to skb
	// @len: length of header to be pushed in front
	// @flags: Flags (unused for now)
	// Return: 0 on success or negative error
	SKBChangeHead
	// XDPAdjustHead - int bpf_xdp_adjust_head(xdp_md, delta)
	// Adjust the xdp_md.data by delta
	// @xdp_md: pointer to xdp_md
	// @delta: An positive/negative integer to be added to xdp_md.data
	// Return: 0 on success or negative on error
	XDPAdjustHead
	// ProbeReadStr - int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
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
	// GetSocketCookie - u64 bpf_get_socket_cookie(skb)
	// Get the cookie for the socket stored inside sk_buff.
	// @skb: pointer to skb
	// Return: 8 Bytes non-decreasing number on success or 0 if the socket
	// field is missing inside sk_buff
	GetSocketCookie
	// GetSocketUID - u32 bpf_get_socket_uid(skb)
	// Get the owner uid of the socket stored inside sk_buff.
	// @skb: pointer to skb
	// Return: uid of the socket owner on success or overflowuid if failed.
	GetSocketUID
	// SetHash - u32 bpf_set_hash(skb, hash)
	// Set full skb->hash.
	// @skb: pointer to skb
	// @hash: hash to set
	SetHash
	// SetSockOpt - int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
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
	// SKBAdjustRoom - int bpf_skb_adjust_room(skb, len_diff, mode, flags)
	// Grow or shrink room in sk_buff.
	// @skb: pointer to skb
	// @len_diff: (signed) amount of room to grow/shrink
	// @mode: operation mode (enum bpf_adj_room_mode)
	// @flags: reserved for future use
	// Return: 0 on success or negative error code
	SKBAdjustRoom
)

// Call emits a function call.
func (fn BuiltinFunc) Call() Instruction {
	return Instruction{
		OpCode:   OpCode(JumpClass).SetJumpOp(Call),
		Constant: int64(fn),
	}
}
