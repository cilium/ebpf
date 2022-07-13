package link

import (
	"math"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

var kprobeMultiSyms = []string{"vprintk", "inet6_release"}

func TestKprobeMulti(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kprobe_multi link")

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti, "")
	opts := KprobeMultiOptions{Symbols: kprobeMultiSyms}

	km, err := KprobeMulti(prog, &opts)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	testLink(t, km, prog)

	opts.Symbols = []string{"bogus"}
	_, err = KprobeMulti(prog, &opts)
	if err == nil {
		t.Fatal("expected err to not be nil")
	}
}

func TestKprobeMultiAddresses(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kprobe_multi link")

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti, "")
	// Only have a negative test for addresses as it would be hard to maintain
	// a proper one.
	// The test correctly fails if the address is set to the start range of perf kallsyms
	// for any symbol:
	//
	// sudo perf kallsyms __x64_sys_getpid
	// __x64_sys_getpid: [kernel] [kernel.kallsyms] 0xffffffffa10f9570-0xffffffffa10f9590 (0xffffffffa10f9570-0xffffffffa10f9590)
	opts := KprobeMultiOptions{Addresses: []uint64{math.MaxUint64}}
	_, err := KprobeMulti(prog, &opts)
	if err == nil {
		t.Fatal("expected err to not be nil")
	}

	opts.Symbols = []string{"bogus"}
	_, err = KprobeMulti(prog, &opts)
	// Assert this is not a link_create error.
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected fail due to Symbols and Addresses being mutual exclusive, got: %v", err)
	}
}

func TestKprobeMultiCookieMismatch(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kprobe_multi link")

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti, "")
	opts := KprobeMultiOptions{
		Symbols: kprobeMultiSyms,
		Cookies: []uint64{1},
	}

	_, err := KprobeMulti(prog, &opts)
	if err == nil {
		t.Fatal("expected err to not be nil")
	}

	opts.Cookies = append(opts.Cookies, 2)
	km, err := KprobeMulti(prog, &opts)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	opts.Cookies = append(opts.Cookies, 3)
	_, err = KprobeMulti(prog, &opts)
	if err == nil {
		t.Fatal("expected err to not be nil")
	}
}

func TestKprobeMultiProgramCall(t *testing.T) {
	m, p := newUpdaterMapProg(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti)

	// For simplicity, just assert the increment happens with any symbol in the array.
	opts := KprobeMultiOptions{
		Symbols: []string{"__do_sys_getpid"},
	}
	km, err := KprobeMulti(p, &opts)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger ebpf program call.
	unix.Getpid()

	// Assert that the value at index 0 has been updated to 1.
	assertMapValue(t, m, 0, 1)

	// Close the link.
	if err := km.Close(); err != nil {
		t.Fatal(err)
	}

	// Reset map value to 0 at index 0.
	if err := m.Update(uint32(0), uint32(0), ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}

	// Retrigger the ebpf program call.
	unix.Getpid()

	// Assert that this time the value has not been updated.
	assertMapValue(t, m, 0, 0)
}

func TestHaveBPFLinkKprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkKprobeMulti)
}