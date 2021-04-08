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

func TestKprobe(t *testing.T) {
	c := qt.New(t)

	prog, err := ebpf.NewProgram(&kprobeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	k, err := Kprobe("printk", prog)
	c.Assert(err, qt.IsNil)
	defer k.Close()

	testLink(t, k, testLinkOptions{
		prog: prog,
	})

	k, err = Kprobe("bogus", prog)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))
	if k != nil {
		k.Close()
	}
}

func TestKretprobe(t *testing.T) {
	c := qt.New(t)

	prog, err := ebpf.NewProgram(&kprobeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	k, err := Kretprobe("printk", prog)
	c.Assert(err, qt.IsNil)
	defer k.Close()

	testLink(t, k, testLinkOptions{
		prog: prog,
	})

	k, err = Kretprobe("bogus", prog)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))
	if k != nil {
		k.Close()
	}
}

func TestKprobeErrors(t *testing.T) {
	c := qt.New(t)

	// Invalid Kprobe incantations. Kretprobe uses the same code paths
	// with a different ret flag.
	_, err := Kprobe("", nil) // empty symbol
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)

	_, err = Kprobe("_", nil) // empty prog
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)

	_, err = Kprobe(".", &ebpf.Program{}) // illegal chars in symbol
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)

	_, err = Kprobe("foo", &ebpf.Program{}) // wrong prog type
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)
}

// Test k(ret)probe creation using perf_kprobe PMU.
func TestKprobeCreatePMU(t *testing.T) {

	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	c := qt.New(t)

	// kprobe happy path. printk is always present.
	pk, err := pmuKprobe("printk", false)
	c.Assert(err, qt.IsNil)
	defer pk.Close()

	c.Assert(pk.progType, qt.Equals, ebpf.Kprobe)

	// kretprobe happy path.
	pr, err := pmuKprobe("printk", true)
	c.Assert(err, qt.IsNil)
	defer pr.Close()

	c.Assert(pr.progType, qt.Equals, ebpf.Kprobe)

	// Expect os.ErrNotExist when specifying a non-existent kernel symbol
	// on kernels 4.17 and up.
	_, err = pmuKprobe("bogus", false)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))

	// A kernel bug was fixed in 97c753e62e6c where EINVAL was returned instead
	// of ENOENT, but only for kretprobes.
	_, err = pmuKprobe("bogus", true)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))
}

// Test fallback behaviour on kernels without perf_kprobe PMU available.
func TestKprobePMUUnavailable(t *testing.T) {
	c := qt.New(t)

	pk, err := pmuKprobe("printk", false)
	if err == nil {
		pk.Close()
		t.Skipf("Kernel supports perf_kprobe PMU, not asserting error.")
	}

	// Only allow a PMU creation with a valid kernel symbol to fail with ErrNotSupported.
	c.Assert(errors.Is(err, ErrNotSupported), qt.IsTrue, qt.Commentf("got error: %s", err))
}

func BenchmarkKprobeCreatePMU(b *testing.B) {
	for n := 0; n < b.N; n++ {
		pr, err := pmuKprobe("printk", false)
		if err != nil {
			b.Error("error creating perf_kprobe PMU:", err)
		}

		if err := pr.Close(); err != nil {
			b.Error("error closing perf_kprobe PMU:", err)
		}
	}
}

// Test tracefs k(ret)probe creation on all kernel versions.
func TestKprobeTraceFS(t *testing.T) {
	c := qt.New(t)

	symbol := "printk"

	// Open and close tracefs k(ret)probes, checking all errors.
	kp, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	c.Assert(kp.Close(), qt.IsNil)
	kp, err = tracefsKprobe(symbol, true)
	c.Assert(err, qt.IsNil)
	c.Assert(kp.Close(), qt.IsNil)

	// Create two identical trace events, ensure their IDs differ.
	k1, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	defer k1.Close()
	c.Assert(k1.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(k1.tracefsID, qt.Not(qt.Equals), 0)

	k2, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	defer k2.Close()
	c.Assert(k2.progType, qt.Equals, ebpf.Kprobe)
	c.Assert(k2.tracefsID, qt.Not(qt.Equals), 0)

	// Compare the kprobes' tracefs IDs.
	c.Assert(k1.tracefsID, qt.Not(qt.CmpEquals()), k2.tracefsID)

	// Write a k(ret)probe event for a non-existing symbol.
	err = createTraceFSKprobeEvent("testgroup", "bogus", false)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))

	// A kernel bug was fixed in 97c753e62e6c where EINVAL was returned instead
	// of ENOENT, but only for kretprobes.
	err = createTraceFSKprobeEvent("testgroup", "bogus", true)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))
}

func BenchmarkKprobeCreateTraceFS(b *testing.B) {
	for n := 0; n < b.N; n++ {
		// Include <tracefs>/kprobe_events operations in the benchmark loop
		// because we create one per perf event.
		pr, err := tracefsKprobe("printk", false)
		if err != nil {
			b.Error("error creating tracefs perf event:", err)
		}

		if err := pr.Close(); err != nil {
			b.Error("error closing tracefs perf event:", err)
		}
	}
}

// Test k(ret)probe creation writing directly to <tracefs>/kprobe_events.
// Only runs on 5.0 and over. Earlier versions ignored writes of duplicate
// events, while 5.0 started returning -EEXIST when a kprobe event already
// exists.
func TestKprobeCreateTraceFS(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "<tracefs>/kprobe_events doesn't reject duplicate events")

	c := qt.New(t)

	symbol := "printk"
	pg, _ := randomGroup("ebpftest")
	rg, _ := randomGroup("ebpftest")

	// Tee up cleanups in case any of the Asserts abort the function.
	defer func() {
		_ = closeTraceFSKprobeEvent(pg, symbol)
		_ = closeTraceFSKprobeEvent(rg, symbol)
	}()

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

	// Expect <prefix>_<16 random hex chars>.
	g, err := randomGroup("ebpftest")
	c.Assert(err, qt.IsNil)
	c.Assert(g, qt.Matches, `ebpftest_[a-f0-9]{16}`)

	// Expect error when the generator's output exceeds 63 characters.
	p := make([]byte, 47) // 63 - 17 (length of the random suffix and underscore) + 1
	for i := range p {
		p[i] = byte('a')
	}
	_, err = randomGroup(string(p))
	c.Assert(err, qt.Not(qt.IsNil))

	// Reject non-alphanumeric characters.
	_, err = randomGroup("/")
	c.Assert(err, qt.Not(qt.IsNil))
}
