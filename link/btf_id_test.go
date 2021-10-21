package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestTraceLSM(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")
	tests := []struct {
		name        string
		attachTo    string
		programType ebpf.ProgramType
		attachType  ebpf.AttachType
	}{
		{
			name:        "AttachTraceFEntry",
			attachTo:    "inet_dgram_connect",
			programType: ebpf.Tracing,
			attachType:  ebpf.AttachTraceFEntry,
		},
		{
			name:        "AttachTraceFExit",
			attachTo:    "inet_dgram_connect",
			programType: ebpf.Tracing,
			attachType:  ebpf.AttachTraceFExit,
		},
		{
			name:        "AttachModifyReturn",
			attachTo:    "bpf_modify_return_test",
			programType: ebpf.Tracing,
			attachType:  ebpf.AttachModifyReturn,
		},
		{
			name:        "AttachTraceRawTp",
			attachTo:    "kfree_skb",
			programType: ebpf.Tracing,
			attachType:  ebpf.AttachTraceRawTp,
		},
		{
			name:        "AttachLSMMac",
			attachTo:    "file_mprotect",
			programType: ebpf.LSM,
			attachType:  ebpf.AttachLSMMac,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type:       tt.programType,
				AttachType: tt.attachType,
				AttachTo:   tt.attachTo,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "GPL",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()

			link, err := AttachTrace(TraceOptions{Program: prog})
			if err != nil {
				t.Fatal(err)
			}

			testLink(t, link, testLinkOptions{
				prog: prog,
				loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
					if tt.attachType != ebpf.AttachTraceRawTp {
						return LoadPinnedTrace(s, opts)
					}
					return LoadPinnedTraceRawTP(s, opts)
				},
			})

			err = link.Close()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
