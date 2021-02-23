CLANG ?= clang
CFLAGS := -target bpf -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all clean
all:: $(addsuffix -el.elf,$(TARGETS)) $(addsuffix -eb.elf,$(TARGETS))

clean::
	-$(RM) *.elf

%-el.elf: %.c
	$(CLANG) $(CFLAGS) -mlittle-endian -c $< -o $@

%-eb.elf : %.c
	$(CLANG) $(CFLAGS) -mbig-endian -c $< -o $@
