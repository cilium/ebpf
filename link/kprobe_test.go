package link

import (
	"errors"
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/tracefs"
	"github.com/cilium/ebpf/internal/unix"
)

// Global symbol, present on all tested kernels.
var ksym = "vprintk"

// Collection of various symbols present in all tested kernels.
// Compiler optimizations result in different names for these symbols.
var symTests = []string{
	"echo_char.isra.0",          // function optimized by -fipa-sra
	"proc_get_long.constprop.0", // optimized function with constant operands
	"unregister_kprobes.part.0", // function body that was split and partially inlined
}

func TestKprobe(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	for _, tt := range symTests {
		t.Run(tt, func(t *testing.T) {
			k, err := Kprobe(tt, prog, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()
		})
	}

	k, err := Kprobe("bogus", prog, nil)
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist), qt.Commentf("got error: %s", err))
	if k != nil {
		k.Close()
	}

	k, err = Kprobe(ksym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer k.Close()

	testLink(t, k, prog)
}

func TestKprobeOffset(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// The layout of a function is compiler and arch dependent, so we try to
	// find a valid attach target in the first few bytes of the function.
	for i := uint64(1); i < 16; i++ {
		k, err := Kprobe("inet6_release", prog, &KprobeOptions{Offset: i})
		if err != nil {
			continue
		}
		k.Close()
		return
	}

	t.Fatal("Can't attach with non-zero offset")
}

func TestKretprobeMaxActive(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")
	defer prog.Close()

	_, err := Kprobe("do_sys_open", prog, &KprobeOptions{RetprobeMaxActive: 4096})
	if !errors.Is(err, tracefs.ErrInvalidMaxActive) {
		t.Fatal("Expected ErrInvalidMaxActive, got", err)
	}

	k, err := Kretprobe("__put_task_struct", prog, &KprobeOptions{RetprobeMaxActive: 4096})
	if testutils.IsKernelLessThan(t, "4.12") && errors.Is(err, ErrNotSupported) {
		t.Skip("Kernel doesn't support maxactive")
	}
	if err != nil {
		t.Fatal("Kretprobe with maxactive returned an error:", err)
	}
	if err := k.Close(); err != nil {
		t.Fatal("Closing kretprobe:", err)
	}
}

func TestKretprobe(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	for _, tt := range symTests {
		t.Run(tt, func(t *testing.T) {
			k, err := Kretprobe(tt, prog, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()
		})
	}

	k, err := Kretprobe("bogus", prog, nil)
	if !(errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.EINVAL)) {
		t.Fatal(err)
	}
	if k != nil {
		k.Close()
	}

	k, err = Kretprobe(ksym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer k.Close()

	testLink(t, k, prog)
}

func TestKprobeErrors(t *testing.T) {
	// Invalid Kprobe incantations. Kretprobe uses the same code paths
	// with a different ret flag.
	_, err := Kprobe("", nil, nil) // empty symbol
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = Kprobe("_", nil, nil) // empty prog
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = Kprobe(".", &ebpf.Program{}, nil) // illegal chars in symbol
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = Kprobe("foo", &ebpf.Program{}, nil) // wrong prog type
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))
}

// Test k(ret)probe creation using perf_kprobe PMU.
func TestKprobeCreatePMU(t *testing.T) {
	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	// kprobe happy path. printk is always present.
	pk, err := pmuProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym})
	qt.Assert(t, qt.IsNil(err))
	defer pk.Close()

	// kretprobe happy path.
	pr, err := pmuProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym, Ret: true})
	qt.Assert(t, qt.IsNil(err))
	defer pr.Close()

	// Expect os.ErrNotExist when specifying a non-existent kernel symbol
	// on kernels 4.17 and up.
	_, err = pmuProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: "bogus"})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist), qt.Commentf("got error: %s", err))

	// A kernel bug was fixed in 97c753e62e6c where EINVAL was returned instead
	// of ENOENT, but only for kretprobes.
	_, err = pmuProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: "bogus", Ret: true})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist), qt.Commentf("got error: %s", err))
}

// Test fallback behaviour on kernels without perf_kprobe PMU available.
func TestKprobePMUUnavailable(t *testing.T) {
	pk, err := pmuProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym})
	if err == nil {
		pk.Close()
		t.Skipf("Kernel supports perf_kprobe PMU, not asserting error.")
	}

	// Only allow a PMU creation with a valid kernel symbol to fail with ErrNotSupported.
	qt.Assert(t, qt.ErrorIs(err, ErrNotSupported), qt.Commentf("got error: %s", err))
}

func BenchmarkKprobeCreatePMU(b *testing.B) {
	for n := 0; n < b.N; n++ {
		pr, err := pmuProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym})
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
	// Open and close tracefs k(ret)probes, checking all errors.
	kp, err := tracefsProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(kp.Close()))

	kp, err = tracefsProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym, Ret: true})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(kp.Close()))

	// Create two identical trace events, ensure their IDs differ.
	k1, err := tracefsProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym})
	qt.Assert(t, qt.IsNil(err))
	defer k1.Close()
	qt.Assert(t, qt.IsNotNil(k1.tracefsEvent))

	k2, err := tracefsProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym})
	qt.Assert(t, qt.IsNil(err))
	defer k2.Close()
	qt.Assert(t, qt.IsNotNil(k2.tracefsEvent))

	// Compare the kprobes' tracefs IDs.
	qt.Assert(t, qt.Not(qt.Equals(k1.tracefsEvent.ID(), k2.tracefsEvent.ID())))

	// Expect an error when supplying an invalid custom group name
	_, err = tracefsProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym, Group: "/"})
	qt.Assert(t, qt.Not(qt.IsNil(err)))

	cg := "customgroup"
	k3, err := tracefsProbe(tracefs.ProbeArgs{Type: tracefs.Kprobe, Symbol: ksym, Group: cg})
	qt.Assert(t, qt.IsNil(err))
	defer k3.Close()
	qt.Assert(t, qt.Matches(k3.tracefsEvent.Group(), `customgroup_[a-f0-9]{16}`))

	// Prepare probe args.
	args := tracefs.ProbeArgs{Type: tracefs.Kprobe, Group: "testgroup", Symbol: "symbol"}

	// Write a k(ret)probe event for a non-existing symbol.
	_, err = tracefs.NewEvent(args)
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist), qt.Commentf("got error: %s", err))

	// A kernel bug was fixed in 97c753e62e6c where EINVAL was returned instead
	// of ENOENT, but only for kretprobes.
	args.Ret = true
	_, err = tracefs.NewEvent(args)
	if !(errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.EINVAL)) {
		t.Fatal(err)
	}
}

func BenchmarkKprobeCreateTraceFS(b *testing.B) {
	for n := 0; n < b.N; n++ {
		// Include <tracefs>/kprobe_events operations in the benchmark loop
		// because we create one per perf event.
		pr, err := tracefsProbe(tracefs.ProbeArgs{Symbol: ksym})
		if err != nil {
			b.Error("error creating tracefs perf event:", err)
		}

		if err := pr.Close(); err != nil {
			b.Error("error closing tracefs perf event:", err)
		}
	}
}

func TestKprobeProgramCall(t *testing.T) {
	m, p := newUpdaterMapProg(t, ebpf.Kprobe, 0)

	// Open Kprobe on `sys_getpid` and attach it
	// to the ebpf program created above.
	k, err := Kprobe("sys_getpid", p, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger ebpf program call.
	unix.Getpid()

	// Assert that the value got incremented to at least 1, while allowing
	// for bigger values, because we could race with other getpid callers.
	assertMapValueGE(t, m, 0, 1)

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

func newUpdaterMapProg(t *testing.T, typ ebpf.ProgramType, attach ebpf.AttachType) (*ebpf.Map, *ebpf.Program) {
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

	// Create ebpf program. When called, will increase the value of key 0 by 1
	// in the map created above.
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: typ,
		Instructions: asm.Instructions{
			// R1 map
			asm.LoadMapPtr(asm.R1, m.FD()),

			// R2 key
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -4),
			asm.StoreImm(asm.R2, 0, 0, asm.Word),

			// Lookup map[0]
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "ret"),

			// u32 val = R0++
			asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
			asm.Add.Imm(asm.R1, 1),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.Word),

			// u32 key = 0
			asm.Mov.Imm(asm.R1, 0),
			asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),

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
			asm.Return().WithSymbol("ret"),
		},
		AttachType: attach,
		License:    "Dual MIT/GPL",
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

func assertMapValueGE(t *testing.T, m *ebpf.Map, k, v uint32) {
	var val uint32
	if err := m.Lookup(k, &val); err != nil {
		t.Fatal(err)
	}
	if val < v {
		t.Fatalf("unexpected value: want >= '%d', got '%d'", v, val)
	}
}

func TestKprobeCookie(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.15", "bpf_perf_link")

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")
	k, err := Kprobe(ksym, prog, &KprobeOptions{Cookie: 1000})
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
}
