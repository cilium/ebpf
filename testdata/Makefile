LLVM_PREFIX ?= /usr/bin
CLANG ?= $(LLVM_PREFIX)/clang
LLC ?= $(LLVM_PREFIX)/llc

all: test.elf

%.elf : %.o
	$(LLC) -march=bpf -filetype=obj -o $@ $<

%.o : %.c
	$(CLANG) -target bpf -O2 -emit-llvm \
		-Wall -Werror \
		-c $< -o $@
