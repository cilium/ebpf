//go:build !windows

package link

import (
	"io"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestIterInfo(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "bpf_map iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "bpf_map")

	it, err := AttachIter(IterOptions{Program: prog})
	qt.Assert(t, qt.IsNil(err))
	defer it.Close()

	info, err := it.Info()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(IterType, info.Type))
	iterInfo := info.Iter()
	qt.Assert(t, qt.Equals(iterInfo.TargetName, "bpf_map"))
}

func TestIter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "bpf_map iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "bpf_map")

	it, err := AttachIter(IterOptions{
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}

	testLink(t, it, prog)
}

func TestIterMapElements(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "bpf_map_elem iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "bpf_map_elem")

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	it, err := AttachIter(IterOptions{
		Program: prog,
		Map:     arr,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}
	defer it.Close()

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}
}

func TestUDPIter(t *testing.T) {
	// Introduced by 5788b3a07fc5 ("net: bpf: Implement bpf iterator for udp")
	testutils.SkipOnOldKernel(t, "5.9", "udp iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "udp")

	it, err := AttachIter(IterOptions{
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}

	testLink(t, it, prog)
}

func TestIterCgroup(t *testing.T) {
	// Introduced by d4ccaf58a847 ("bpf: Introduce cgroup iter")
	testutils.SkipOnOldKernel(t, "6.1", "cgroup iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "cgroup")
	cgroup := testutils.CreateCgroup(t)

	for _, tc := range []struct {
		name  string
		order CgroupIterOrder
	}{
		{"self", CgroupIterSelfOnly},
		{"pre", CgroupIterDescendantsPre},
		{"post", CgroupIterDescendantsPost},
		{"up", CgroupIterAncestorsUp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			it, err := AttachIter(IterOptions{
				Program: prog,
				Cgroup:  &CgroupIterOptions{Order: tc.order, Path: cgroup.Name()},
			})
			qt.Assert(t, qt.IsNil(err))
			defer it.Close()

			file, err := it.Open()
			qt.Assert(t, qt.IsNil(err))
			defer file.Close()

			contents, err := io.ReadAll(file)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.HasLen(contents, 0))
		})
	}

	it, err := AttachIter(IterOptions{
		Program: prog,
		Cgroup: &CgroupIterOptions{
			Order: CgroupIterSelfOnly,
			ID:    testutils.GetCgroupIno(t, cgroup),
		},
	})
	qt.Assert(t, qt.IsNil(err))
	defer it.Close()

	testLink(t, it, prog)
}
