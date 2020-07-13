all: build-ebpf build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-O2 -emit-llvm \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	go-bindata -pkg main -prefix "ebpf/bin" -o "probe.go" "ebpf/bin/probe.o"

build:
	go build -o bin/main .

run:
	sudo bin/main --kill
