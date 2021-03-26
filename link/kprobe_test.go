package link

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	qt "github.com/frankban/quicktest"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

var (
	kprobeSpec = ebpf.ProgramSpec{
		Type:    ebpf.Kprobe,
		License: "MIT",
		Instructions: asm.Instructions{
			// set exit code to 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}
)

func TestKprobeAttach(t *testing.T) {

	//TODO: implement kprobe program version rewriting for pre-5.0 kernels.
	// Requires at least 5.0 (6c4fc209fcf9 "bpf: remove useless version check for prog load")
	testutils.SkipOnOldKernel(t, "5.0", "lifted version check for kprobes")

	c := qt.New(t)

	prog, err := ebpf.NewProgram(&kprobeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	tp, err := Kprobe("printk")
	c.Assert(err, qt.IsNil)
	c.Assert(tp.ret, qt.Equals, false) // must be a kprobe, not kretprobe.
	defer tp.Close()

	l, err := tp.Attach(prog)
	c.Assert(err, qt.IsNil)
	defer l.Close()
}

func TestKretprobeAttach(t *testing.T) {

	//TODO: implement kprobe program version rewriting for pre-5.0 kernels.
	// Requires at least 5.0 (6c4fc209fcf9 "bpf: remove useless version check for prog load")
	testutils.SkipOnOldKernel(t, "5.0", "lifted version check for kprobes")

	c := qt.New(t)

	prog, err := ebpf.NewProgram(&kprobeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	tp, err := Kretprobe("printk")
	c.Assert(err, qt.IsNil)
	c.Assert(tp.ret, qt.Equals, true) // kretprobe
	defer tp.Close()

	l, err := tp.Attach(prog)
	c.Assert(err, qt.IsNil)
	defer l.Close()
}

func TestKprobeTraceEvent(t *testing.T) {
	tp, err := kprobe("printk", false)
	if err != nil {
		t.Fatal("creating kprobe:", err)
	}
	defer tp.Close()
}

// Test k(ret)probe creation using perf_kprobe PMU.
func TestKprobeCreatePMU(t *testing.T) {

	// Requires at least 4.15 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.15", "perf_kprobe PMU")

	c := qt.New(t)

	// kprobe happy path. printk is always present.
	pk, err := pmuKprobe("printk", false)
	c.Assert(err, qt.IsNil)
	defer pk.Close()

	c.Assert(pk.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(pk.finalizer, qt.IsNil)

	pe, err := pk.perfEventOpenPMU()
	c.Assert(err, qt.IsNil)
	defer unix.Close(pe)

	// kretprobe happy path.
	pr, err := pmuKprobe("printk", true)
	c.Assert(err, qt.IsNil)
	defer pr.Close()

	c.Assert(pr.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(pr.finalizer, qt.IsNil)

	pe, err = pr.perfEventOpenPMU()
	c.Assert(err, qt.IsNil)
	defer unix.Close(pe)
}

// Test k(ret)probe creation handling pre-existing trace events.
func TestKprobeTraceFS(t *testing.T) {
	c := qt.New(t)

	symbol := "printk"
	group := mustRandomGroup("ebpftest")

	// First call using this group and symbol will write to <tracefs>/kprobe_events.
	// The TraceEvent must contain a finalizer to remove the record on Close.
	te, err := tracefsKprobe(group, symbol, false)
	c.Assert(err, qt.IsNil)
	defer te.Close()
	c.Assert(te.finalizer, qt.Not(qt.IsNil))
	c.Assert(te.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(te.tracefsID, qt.Not(qt.Equals), 0)

	// Second invocation. Identical trace event already exists,
	// so must not contain a finalizer
	te, err = tracefsKprobe(group, symbol, false)
	c.Assert(err, qt.IsNil)
	defer te.Close()
	c.Assert(te.finalizer, qt.IsNil)
}

// Test k(ret)probe creation unconditionally writing to <tracefs>/kprobe_events.
func TestKprobeCreateTraceFS(t *testing.T) {
	c := qt.New(t)

	symbol := "printk"
	group := mustRandomGroup("ebpftest")

	// Create a kprobe.
	err := createTraceFSKprobeEvent(group, symbol, false)
	c.Assert(err, qt.IsNil)
	// Create a kretprobe on the same symbol using the same group.
	err = createTraceFSKprobeEvent(group, symbol, true)
	c.Assert(err, qt.IsNil)

	// Attempt to create an identical kprobe using tracefs,
	// expect it to fail with os.ErrExist.
	err = createTraceFSKprobeEvent(group, symbol, false)
	c.Assert(err, qt.Not(qt.IsNil))
	// Don't bail out here, the close(s) below needs to fire to avoid dangling
	// kprobes in <tracefs>/kprobe_events.
	c.Check(errors.Is(err, os.ErrExist), qt.IsTrue,
		qt.Commentf("expected consecutive kprobe creation to contain os.ErrExist, got: %v", err))

	// Same for kretprobe, expect os.ErrExist.
	err = createTraceFSKprobeEvent(group, symbol, true)
	c.Assert(err, qt.Not(qt.IsNil))
	c.Check(os.IsExist(err), qt.IsFalse,
		qt.Commentf("expected consecutive kprobe creation to contain os.ErrExist, got: %v", err))

	err = closeTraceFSKprobeEvent(group, symbol, false)
	c.Assert(err, qt.IsNil)
	err = closeTraceFSKprobeEvent(group, symbol, true)
	c.Assert(err, qt.IsNil)

	err = createTraceFSKprobeEvent("syscalls", "bogus", false)
	c.Assert(errors.Is(err, ErrNotSupported), qt.IsTrue)
}

func TestKprobeTraceFSGroup(t *testing.T) {
	c := qt.New(t)

	// Expect <prefix>_<8 random hex chars>.
	c.Assert(mustRandomGroup("ebpftest"), qt.Matches, `ebpftest_[a-f0-9]{8}`)

	// Expect panic when the generator's output exceeds 63 characters.
	c.Assert(func() { mustRandomGroup(string(make([]byte, 55))) }, qt.PanicMatches, `.*`)

	// Expect panic when using non-alphanum character in group name.
	c.Assert(func() { mustRandomGroup("/") }, qt.PanicMatches, `.*`)
}
