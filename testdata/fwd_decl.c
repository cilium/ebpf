/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

// Forward function declaration, never implemented.
int fwd();

__section("socket") int call_fwd() {
	return fwd();
}
