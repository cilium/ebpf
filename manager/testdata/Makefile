LLVM_PREFIX ?= /usr/bin
CLANG ?= $(LLVM_PREFIX)/clang

all: rewrite.elf

clean:
	-$(RM) *.elf

%.elf : %.c
	$(CLANG) -target bpf -O2 -g \
		-Wall -Werror \
		-c $< -o $@
