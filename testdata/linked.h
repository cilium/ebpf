#pragma once

#include "common.h"

/* When linking BTF map definitions, all maps must be compatible with each
 * other, otherwise bpftool throws an error. */
struct h32_btf {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
};

/* Legacy map definitions are appended like programs sections are, and can
 * win/lose based on linking order, even if they're completely different maps.
 * Test whether the expected candidate wins by configuring different maxentries.
 */
#define h32_legacy(MAX_ENTRIES) \
{ \
        .type        = BPF_MAP_TYPE_HASH, \
        .key_size    = sizeof(int), \
        .value_size  = sizeof(int), \
        .max_entries = MAX_ENTRIES, \
        .map_flags   = BPF_F_NO_PREALLOC, \
}
