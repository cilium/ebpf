CLANG := clang-11

TARGETS := relocs

include $(CURDIR)/../../../testdata/base.mk

# Usage: make KDIR=/path/to/foo vmlinux-btf.gz
vmlinux-btf.gz: $(KDIR)/vmlinux
	objcopy --dump-section .BTF=/dev/stdout "$<" | gzip > "$@"
