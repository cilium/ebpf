LLVM_PREFIX ?= /usr/bin
CLANG ?= $(LLVM_PREFIX)/clang
LLC ?= $(LLVM_PREFIX)/llc

all: loader.elf rewrite.elf perf_output.elf

clean:
	-$(RM) *.elf

%.elf : %.o
	$(LLC) -march=bpf -filetype=obj -o $@ $<

%.o : %.c
	$(CLANG) -target bpf -O2 -emit-llvm -g \
		-Wall -Werror \
		-c $< -o $@
