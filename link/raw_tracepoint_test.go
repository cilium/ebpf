package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT API")

	prog := mustLoadProgram(t, ebpf.RawTracepoint, 0, "")

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, prog)
}

func TestRawTracepoint_writable(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.2", "BPF_RAW_TRACEPOINT_WRITABLE API")

	prog := mustLoadProgram(t, ebpf.RawTracepoint, 0, "")

	defer prog.Close()

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_rmdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, prog)
}
