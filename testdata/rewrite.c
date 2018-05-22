/* This file tests rewriting constants from C compiled code.
 */

#define __section(NAME) __attribute__((section(NAME), used))

char __license[] __section("license") = "MIT";

const unsigned long long_val;
const unsigned int int_val;

__section("xdp") int xdp_prog() {
	if (long_val < 5) {
		return 1;
	}

	return int_val;
}
