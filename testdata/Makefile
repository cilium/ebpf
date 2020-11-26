LLVM_PREFIX ?= /usr/bin
CLANG ?= $(LLVM_PREFIX)/clang
CFLAGS := -target bpf -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all clean
all: loader-clang-6.0-el.elf loader-clang-7-el.elf loader-clang-8-el.elf loader-clang-9-el.elf invalid_map-el.elf raw_tracepoint-el.elf invalid_map_static-el.elf \
	loader-clang-6.0-eb.elf loader-clang-7-eb.elf loader-clang-8-eb.elf loader-clang-9-eb.elf invalid_map-eb.elf raw_tracepoint-eb.elf invalid_map_static-eb.elf

clean:
	-$(RM) *.elf

loader-%-el.elf: loader.c
	$* $(CFLAGS) -mlittle-endian -c $< -o $@

loader-%-eb.elf: loader.c
	$* $(CFLAGS) -mbig-endian -c $< -o $@

%-el.elf: %.c
	$(CLANG) $(CFLAGS) -mlittle-endian -c $< -o $@

%-eb.elf : %.c
	$(CLANG) $(CFLAGS) -mbig-endian -c $< -o $@
