//go:build amd64
// +build amd64

package link

import (
	"errors"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestKprobeOffset(t *testing.T) {
	// skip test on 4.4 and 4.9 as the offsets are different
	// even if the function implementation hasn't changed:
	//
	// ffffffff81690670 <inet6_release>:
	// ffffffff81690670:	e8 eb c0 15 00       	call   ffffffff817ec760 <__fentry__>
	// ffffffff81690675:	55                   	push   %rbp
	// ffffffff81690676:	48 89 e5             	mov    %rsp,%rbp
	// ffffffff81690679:	41 55                	push   %r13
	// ffffffff8169067b:	41 54                	push   %r12
	// snip
	testutils.SkipOnOldKernel(t, "4.10", "n/a")

	tests := []struct {
		name   string
		offset uint64
		err    error
	}{
		// cat /boot/System.map-$(uname -r) |rg inet6_release
		// ffffffff81b97c10 T inet6_release
		//
		// ./extract-vmlinux /boot/vmlinuz-$(uname -r) > /tmp/vmlinux
		//
		// objdump -D /tmp/vmlinux |rg ffffffff81b97c
		// ffffffff81b97c10:	e8 4b fc 4c ff       	call   0xffffffff81067860
		// ffffffff81b97c15:	41 54                	push   %r12
		// ffffffff81b97c17:	55                   	push   %rbp
		// ffffffff81b97c18:	4c 8b 67 18          	mov    0x18(%rdi),%r12
		// snip
		// ffffffff81b97c27:	e8 c4 ae 03 00       	call   0xffffffff81bd2af0
		// snip
		// ffffffff81b97c47:	c3                   	ret
		{"valid offset", 0x5, nil},
		{"valid offset", 0x7, nil},
		// ipv6_sock_mc_close()
		{"valid offset", 0x17, nil},
		{"bad insn boundary", 0x4, os.ErrNotExist},
		{"bad insn boundary", 0x6, os.ErrNotExist},
		{"bad probe address", math.MaxUint64, os.ErrNotExist},
	}

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := Kprobe("inet6_release", prog, &KprobeOptions{Offset: tt.offset})
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Errorf("expected err '%v', got '%v'", tt.err, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected err: '%v'", err)
			}
			k.Close()
		})
	}
}
