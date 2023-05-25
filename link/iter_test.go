package link

import (
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

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
