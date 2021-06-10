package link

import (
	"errors"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
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

	c.Assert(pk.typ, qt.Equals, kprobeEvent)

	// kretprobe happy path.
	pr, err := pmuKprobe("printk", true)
	c.Assert(err, qt.IsNil)
	defer pr.Close()

	c.Assert(pr.typ, qt.Equals, kretprobeEvent)

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
	c.Assert(kp.typ, qt.Equals, kprobeEvent)

	kp, err = tracefsKprobe(symbol, true)
	c.Assert(err, qt.IsNil)
	c.Assert(kp.Close(), qt.IsNil)
	c.Assert(kp.typ, qt.Equals, kretprobeEvent)

	// Create two identical trace events, ensure their IDs differ.
	k1, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	defer k1.Close()
	c.Assert(k1.tracefsID, qt.Not(qt.Equals), 0)

	k2, err := tracefsKprobe(symbol, false)
	c.Assert(err, qt.IsNil)
	defer k2.Close()
	c.Assert(k2.tracefsID, qt.Not(qt.Equals), 0)

	// Compare the kprobes' tracefs IDs.
	c.Assert(k1.tracefsID, qt.Not(qt.CmpEquals()), k2.tracefsID)

	// Write a k(ret)probe event for a non-existing symbol.
	err = createTraceFSProbeEvent(kprobeType, "testgroup", "bogus", "", 0, false)
	c.Assert(errors.Is(err, os.ErrNotExist), qt.IsTrue, qt.Commentf("got error: %s", err))

	// A kernel bug was fixed in 97c753e62e6c where EINVAL was returned instead
	// of ENOENT, but only for kretprobes.
	err = createTraceFSProbeEvent(kprobeType, "testgroup", "bogus", "", 0, true)
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
		_ = closeTraceFSProbeEvent(kprobeType, pg, symbol)
		_ = closeTraceFSProbeEvent(kprobeType, rg, symbol)
	}()

	// Create a kprobe.
	err := createTraceFSProbeEvent(kprobeType, pg, symbol, "", 0, false)
	c.Assert(err, qt.IsNil)

	// Attempt to create an identical kprobe using tracefs,
	// expect it to fail with os.ErrExist.
	err = createTraceFSProbeEvent(kprobeType, pg, symbol, "", 0, false)
	c.Assert(errors.Is(err, os.ErrExist), qt.IsTrue,
		qt.Commentf("expected consecutive kprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kprobe.
	c.Assert(closeTraceFSProbeEvent(kprobeType, pg, symbol), qt.IsNil)

	// Same test for a kretprobe.
	err = createTraceFSProbeEvent(kprobeType, rg, symbol, "", 0, true)
	c.Assert(err, qt.IsNil)

	err = createTraceFSProbeEvent(kprobeType, rg, symbol, "", 0, true)
	c.Assert(os.IsExist(err), qt.IsFalse,
		qt.Commentf("expected consecutive kretprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kretprobe.
	c.Assert(closeTraceFSProbeEvent(kprobeType, rg, symbol), qt.IsNil)
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

func TestDetermineRetprobeBit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")
	c := qt.New(t)

	rpk, err := kretprobeBit()
	c.Assert(err, qt.IsNil)
	c.Assert(rpk, qt.Equals, uint64(0))

	rpu, err := uretprobeBit()
	c.Assert(err, qt.IsNil)
	c.Assert(rpu, qt.Equals, uint64(0))
}

func TestKprobeProgramCall(t *testing.T) {
	m, p := newUpdaterMapProg(t, ebpf.Kprobe)

	// Open Kprobe on `sys_getpid` and attach it
	// to the ebpf program created above.
	k, err := Kprobe("sys_getpid", p)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger ebpf program call.
	unix.Getpid()

	// Assert that the value at index 0 has been updated to 1.
	assertMapValue(t, m, 0, 1)

	// Detach the Kprobe.
	if err := k.Close(); err != nil {
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

func newUpdaterMapProg(t *testing.T, typ ebpf.ProgramType) (*ebpf.Map, *ebpf.Program) {
	// Create ebpf map. Will contain only one key with initial value 0.
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create ebpf program. When called, will set the value of key 0 in
	// the map created above to 1.
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: typ,
		Instructions: asm.Instructions{
			// u32 key = 0
			asm.Mov.Imm(asm.R1, 0),
			asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),

			// u32 val = 1
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.Word),

			// bpf_map_update_elem(...)
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -8),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnMapUpdateElem.Call(),

			// exit 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Dual MIT/GPL",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close the program and map on test teardown.
	t.Cleanup(func() {
		m.Close()
		p.Close()
	})

	return m, p
}

func assertMapValue(t *testing.T, m *ebpf.Map, k, v uint32) {
	var val uint32
	if err := m.Lookup(k, &val); err != nil {
		t.Fatal(err)
	}
	if val != v {
		t.Fatalf("unexpected value: want '%d', got '%d'", v, val)
	}
}
