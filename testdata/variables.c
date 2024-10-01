#include "common.h"

// Should not appear in CollectionSpec.Variables.
__hidden volatile uint32_t hidden;

// Weak variables can be overridden by non-weak symbols when linking BPF
// programs using bpftool. Make sure they appear in CollectionSpec.Variables.
__weak volatile uint32_t weak __section(".data.weak");

// Ensure vars are referenced so they are not culled by the loader.
__section("socket") int set_vars() {
	hidden = 0xbeef1;
	weak   = 0xbeef2;
	return 0;
}

volatile uint32_t var_bss __section(".bss");
__section("socket") int get_bss() {
	return var_bss;
}
volatile uint32_t var_data __section(".data");
__section("socket") int get_data() {
	return var_data;
}
volatile const uint32_t var_rodata __section(".rodata");
__section("socket") int get_rodata() {
	return var_rodata;
}

struct var_struct_t {
	uint64_t a;
	uint64_t b;
};
volatile struct var_struct_t var_struct __section(".data.struct");
__section("socket") int check_struct() {
	return var_struct.a == 0xa && var_struct.b == 0xb;
}

/* Padding before b and after 1-byte-aligned d. */
struct var_struct_pad_t {
	uint32_t a;
	uint64_t b;
	uint16_t c;
	uint8_t d[5];
	uint64_t e;
};
volatile struct var_struct_pad_t var_struct_pad __section(".data.struct");
__section("socket") int check_struct_pad() {
	return var_struct_pad.a == 0xa && var_struct_pad.b == 0xb && var_struct_pad.c == 0xc && var_struct_pad.d[0] == 0xd && var_struct_pad.e == 0xe;
}

// Variable aligned on page boundary to ensure all bytes in the mapping can be
// accessed through the Variable API.
volatile uint8_t var_array[8192] __section(".data.array");
__section("socket") int check_array() {
	return var_array[sizeof(var_array) - 1] == 0xff;
}

volatile uint32_t var_atomic __section(".data.atomic");
__section("socket") int add_atomic() {
	__sync_fetch_and_add(&var_atomic, 1);
	return 0;
}
