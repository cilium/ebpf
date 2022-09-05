package link

import (
	"errors"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

var kprobeMultiSyms = []string{"vprintk", "inet6_release"}

func TestKprobeMulti(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kprobe_multi link")

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti, "")

	km, err := KprobeMulti(prog, KprobeMultiOptions{Symbols: kprobeMultiSyms})
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	testLink(t, km, prog)
}

func TestKprobeMultiErrors(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti, "")

	// Symbols and Addresses are mutually exclusive.
	_, err := KprobeMulti(prog, KprobeMultiOptions{
		Symbols:   []string{"foo"},
		Addresses: []uint64{1},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}

	_, err = KprobeMulti(prog, KprobeMultiOptions{
		Cookies: []uint64{1},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}

	_, err = KprobeMulti(prog, KprobeMultiOptions{Symbols: []string{"bogus"}})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist, got: %s", err)
	}

	// Only have a negative test for addresses as it would be hard to maintain a
	// proper one.
	if _, err := KprobeMulti(prog, KprobeMultiOptions{
		Addresses: []uint64{math.MaxUint64},
	}); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected EINVAL, got: %s", err)
	}
}

func TestKprobeMultiCookie(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kprobe_multi link")

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti, "")

	if _, err := KprobeMulti(prog, KprobeMultiOptions{
		Symbols: kprobeMultiSyms,
		Cookies: []uint64{0, 1},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKprobeMultiProgramCall(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kprobe_multi link")

	m, p := newUpdaterMapProg(t, ebpf.Kprobe, ebpf.AttachTraceKprobeMulti)

	// For simplicity, just assert the increment happens with any symbol in the array.
	opts := KprobeMultiOptions{
		Symbols: []string{"__do_sys_getpid"},
	}
	km, err := KprobeMulti(p, opts)
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
