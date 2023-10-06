/* This file exercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

char __license[] __section("license") = "MIT";

/*
 * Maps with the Freeze flag set (like .rodata) must be frozen before sending
 * programs to the verifier so constants can be used during verification. If
 * done incorrectly, the following sk_lookup program will fail to verify since
 * the only valid return code is 1. See bpf/verifier.c:check_return_code().
 */
volatile const uint32_t ret = -1;
__section("sk_lookup/") int freeze_rodata() {
	return ret;
}
