//go:build !windows

package link

import (
	"testing"

	"github.com/go-quicktest/qt"

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

func TestRawTracepointInfo(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "bpf_link_info_raw_tracepoint")

	prog := mustLoadProgram(t, ebpf.RawTracepoint, 0, "")

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()

	info, err := link.Info()
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(RawTracepointType, info.Type))
	tpInfo := info.RawTracepoint()
	qt.Assert(t, qt.Equals(tpInfo.Name, "cgroup_mkdir"))
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
