/* This file tests rewriting constants from C compiled code.
 */

#define __section(NAME) __attribute__((section(NAME), used))

char __license[] __section("license") = "MIT";

const unsigned long long_val;
const unsigned int int_val;
const unsigned short short_val;

const unsigned long long_array[0];

__section("xdp") int xdp_prog() {
	if (long_val < 5) {
		return 1;
	}

	if (short_val < 5) {
		return 2;
	}

	return int_val;
}

__section("xdp/invalid") int invalid_xdp_prog() {
	if (int_val < 5) {
		return 1;
	}

	return long_array[2];
}
