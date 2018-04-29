# Build BPF programs by using the kernel build system.
#    make kernel_src=/path/to/kernel/src

# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# Tell kbuild to always build the programs
always += sockex1_kern.o

HOSTCFLAGS += -I$(objtree)/usr/include
HOSTCFLAGS += -I$(srctree)/tools/lib/
HOSTCFLAGS += -I$(srctree)/tools/perf

HOSTCFLAGS_bpf_load.o += -I$(objtree)/usr/include -Wno-unused-variable
HOSTLOADLIBES_sockex1 += -lelf

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLVM_PREFIX ?= /usr/bin
CLANG ?= $(LLVM_PREFIX)/clang
LLC ?= $(LLVM_PREFIX)/llc

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C $(kernel_src) $(CURDIR)/

clean:
	$(MAKE) -C $(kernel_src) M=$(CURDIR) clean
	@rm -f *~

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
$(obj)/%.o: $(src)/%.c
	$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-O2 -S -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
