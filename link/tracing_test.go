package link

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestFreplace(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.10", "freplace")

	testutils.Files(t, testutils.Glob(t, "../testdata/freplace-*.elf"), func(t *testing.T, file string) {
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
		}

		target, err := ebpf.NewProgram(spec.Programs["sched_process_exec"])
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create target program:", err)
		}
		defer target.Close()

		// Test attachment specified at load time
		spec.Programs["replacement"].AttachTarget = target
		replacement, err := ebpf.NewProgram(spec.Programs["replacement"])
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create replacement program:", err)
		}
		defer replacement.Close()

		freplace, err := AttachFreplace(nil, "", replacement)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create freplace:", err)
		}

		testLink(t, freplace, replacement)
	})
}

func TestTracing(t *testing.T) {
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
	}

	test := func(
		t *testing.T,
		method string,
		pt ebpf.ProgramType,
		at ebpf.AttachType,
		ato string,
		atOpt ebpf.AttachType) {
		prog := mustLoadProgram(t, pt, at, ato)
		link, err := AttachTracing(TracingOptions{Program: prog, AttachType: atOpt})
		err2 := fmt.Errorf("%s: %w", method, err)
		testutils.SkipIfNotSupported(t, err2)
		if err != nil {
			t.Fatal(err2)
		}
		testLink(t, link, prog)
		if err = link.Close(); err != nil {
			t.Fatal(err)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// exercise attach via BPF link
			test(t, "bpf_link", tt.programType, tt.attachType, tt.attachTo, tt.attachType)
			// exercise legacy attach via RawTracepointOpen
			test(t, "raw_tracepoint_open", tt.programType, tt.attachType, tt.attachTo, ebpf.AttachNone)
		})
	}
}

func TestLSM(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

	prog := mustLoadProgram(t, ebpf.LSM, ebpf.AttachLSMMac, "file_mprotect")

	link, err := AttachLSM(LSMOptions{Program: prog})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, prog)
}
