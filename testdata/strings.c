#include "common.h"

char __license[] __section("license") = "MIT";

#define STR1 "This string is allocated in the string section\n"
#define STR2 "This one too\n"

__section("socket") int filter() {
	trace_printk(STR1, sizeof(STR1));
	trace_printk(STR2, sizeof(STR2));
	return 0;
}
