package link

import (
	"errors"
	"os"
	"testing"

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

	pe, err := pk.perfEventOpenPMU()
	c.Assert(err, qt.IsNil)
	defer pe.Close()

	// kretprobe happy path.
	pr, err := pmuKprobe("printk", true)
	c.Assert(err, qt.IsNil)
	defer pr.Close()

	c.Assert(pr.progType, qt.Equals, ebpf.Kprobe)

	pe, err = pr.perfEventOpenPMU()
	c.Assert(err, qt.IsNil)
	defer pe.Close()
}

func BenchmarkKprobeCreatePMU(b *testing.B) {
	pr, err := pmuKprobe("printk", false)
	if err != nil {
		b.Error("error getting kprobe PMU type:", err)
	}
	defer pr.Close()

	for n := 0; n < b.N; n++ {
		fd, err := pr.perfEventOpenPMU()
		if err != nil {
			b.Error("error creating PMU perf event:", err)
		}

		if err := fd.Close(); err != nil {
			b.Error("error closing PMU perf event:", err)
		}
	}
}

// Test tracefs k(ret)probe creation on all kernel versions.
// Create two trace events on the same symbol and ensure their IDs differ.
func TestKprobeTraceFS(t *testing.T) {
	c := qt.New(t)

	symbol := "printk"

	// Open and close tracefs kprobe, checking all errors.
	te, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	c.Assert(te.Close(), qt.IsNil)

	// Create similar trace events, ensure their IDs differ.
	te1, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	defer te1.Close()
	c.Assert(te1.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(te1.tracefsID, qt.Not(qt.Equals), 0)

	te2, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	defer te2.Close()
	c.Assert(te2.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(te2.tracefsID, qt.Not(qt.Equals), 0)

	c.Assert(te1.tracefsID, qt.Not(qt.CmpEquals()), te2.tracefsID)

	// Write a kprobe event for a non-existing symbol.
	err = createTraceFSKprobeEvent("syscalls", "bogus", false)
	c.Assert(errors.Is(err, ErrNotSupported), qt.IsTrue)
}

func BenchmarkKprobeCreateTraceFS(b *testing.B) {
	for n := 0; n < b.N; n++ {

		// Include <tracefs>/kprobe_events operations in the benchmark loop
		// because we create one per perf event.
		pr, err := tracefsKprobe("printk", false)
		if err != nil {
			b.Error("error creating tracefs trace event:", err)
		}
		defer pr.Close()

		fd, err := pr.perfEventOpenTraceFS()
		if err != nil {
			b.Error("error creating tracefs-backed perf event:", err)
		}

		if err := fd.Close(); err != nil {
			b.Error("error closing tracefs perf event:", err)
		}
	}
}

// Test k(ret)probe creation writing durectly to <tracefs>/kprobe_events.
// Only runs on 5.0 and over. Earlier versions ignored writes of duplicate
// events, while 5.0 started returning -EEXIST when a kprobe event already
// exists.
func TestKprobeCreateTraceFS(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "<tracefs>/kprobe_events doesn't reject duplicate events")

	c := qt.New(t)

	symbol := "printk"
	pg := mustRandomGroup("ebpftest")
	rg := mustRandomGroup("ebpftest")

	// Tee up cleanups in case any of the Asserts abort the function.
	defer func() { _ = closeTraceFSKprobeEvent(pg, symbol) }()
	defer func() { _ = closeTraceFSKprobeEvent(rg, symbol) }()

	// Create a kprobe.
	err := createTraceFSKprobeEvent(pg, symbol, false)
	c.Assert(err, qt.IsNil)

	// Attempt to create an identical kprobe using tracefs,
	// expect it to fail with os.ErrExist.
	err = createTraceFSKprobeEvent(pg, symbol, false)
	c.Assert(errors.Is(err, os.ErrExist), qt.IsTrue,
		qt.Commentf("expected consecutive kprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kprobe.
	c.Assert(closeTraceFSKprobeEvent(pg, symbol), qt.IsNil)

	// Same test for a kretprobe.
	err = createTraceFSKprobeEvent(rg, symbol, true)
	c.Assert(err, qt.IsNil)

	err = createTraceFSKprobeEvent(rg, symbol, true)
	c.Assert(os.IsExist(err), qt.IsFalse,
		qt.Commentf("expected consecutive kretprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kretprobe.
	c.Assert(closeTraceFSKprobeEvent(rg, symbol), qt.IsNil)

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
