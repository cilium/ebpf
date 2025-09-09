/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 100); /* number of pages */
	__ulong(map_extra, 0x1ull << 44); /* start of mmap region */
} arena __section(".maps");
