#include "common.h"

char __license[] __section("license") = "MIT";

// volatile consts can be overwritten by cilium
volatile const bool var1 = 1;

volatile const __s8 var2  = -1;
volatile const __s16 var3 = -2;
volatile const __s32 var4 = -3;
volatile const __s64 var5 = -4;

volatile const __u8 var6  = 1;
volatile const __u16 var7 = 2;
volatile const __u32 var8 = 3;
volatile const __u64 var9 = 4;

__section("socket/main") int filter() {
	if (var1)
		return 0;
	if (var2 > 0)
		return 0;
	if (var3 > 0)
		return 0;
	if (var4 > 0)
		return 0;
	if (var5 > 0)
		return 0;
	if (var6 > 0)
		return 0;
	if (var7 > 0)
		return 0;
	if (var8 > 0)
		return 0;
	if (var9 > 0)
		return 0;
	return 1;
}
