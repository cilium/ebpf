CLANG ?= clang
CFLAGS := -target bpf -O2 -g -Wall -Werror $(CFLAGS)

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

.PHONY: all clean
all: $(addsuffix -el.elf,$(TARGETS)) $(addsuffix -eb.elf,$(TARGETS))

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
