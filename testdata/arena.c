/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

// char _license[] __section("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* number of pages */
	__ulong(map_extra, 0x1ULL << 44); /* start of mmap region */
} arena __section(".maps");

__section("syscall") int test_arena_cast(void *ctx) {
	void *map = &arena;
	asm volatile("" : "+r"(map));

	void __arena *arena_ptr = (void __arena *)0x1000;
	void *generic_ptr       = (void *)arena_ptr;

	return (map && generic_ptr) ? 1 : 0;
}
