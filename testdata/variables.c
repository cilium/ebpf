#include "common.h"

// Should not appear in CollectionSpec.Variables.
__hidden volatile uint32_t hidden;

// Should also not appear in CollectionSpec.Variables. Put into its own section
// to avoid this ending up in .bss where references to other symbols in .bss
// would overlap, incorrectly preventing it from being culled by the loader.
volatile uint32_t unreferenced __section(".data.unref");

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
