TARGETS := loader-clang-6.0 \
	loader-clang-8 \
	loader-clang-9 \
	loader-clang-10 \
	loader-clang-11 \
	invalid_map \
	raw_tracepoint \
	invalid_map_static \
	initialized_btf_map \
	strings

include $(CURDIR)/base.mk

loader-%-el.elf: loader.c
	$* $(CFLAGS) -mlittle-endian -c $< -o $@

loader-%-eb.elf: loader.c
	$* $(CFLAGS) -mbig-endian -c $< -o $@
