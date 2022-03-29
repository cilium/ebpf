/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

#define PIN_GLOBAL_NS 2

// bpf_elf_map is a custom BPF map definition used by iproute2.
// It contains the id, pinning, inner_id and inner_idx fields
// in addition to the ones in struct bpf_map_def which is commonly
// used in the kernel and libbpf.
struct bpf_elf_map {
	unsigned int type;
	unsigned int size_key;
	unsigned int size_value;
	unsigned int max_elem;
	unsigned int flags;
	unsigned int id;
	unsigned int pinning;
	unsigned int inner_id;
	unsigned int inner_idx;
};

struct bpf_elf_map hash_map __section("maps") = {
	.type       = BPF_MAP_TYPE_HASH,
	.size_key   = sizeof(uint32_t),
	.size_value = sizeof(uint64_t),
	.max_elem   = 2,
	.pinning    = PIN_GLOBAL_NS,
};
