package link

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

var bashEx, _ = OpenExecutable("/bin/bash")
var bashSym = "main"

func TestExecutable(t *testing.T) {
	_, err := OpenExecutable("")
	if err == nil {
		t.Fatal("create executable: expected error on empty path")
	}

	if bashEx.path != "/bin/bash" {
		t.Fatalf("create executable: unexpected path '%s'", bashEx.path)
	}

	sym, err := bashEx.symbol(bashSym)
	if err != nil {
		t.Fatalf("find symbol: %v", err)
	}
	if sym.Name != bashSym {
		t.Fatalf("find symbol: unexpected symbol '%s'", sym.Name)
	}

	_, err = bashEx.symbol("bogus")
	if err == nil {
		t.Fatal("find symbol: expected error")
	}
}

func TestUprobe(t *testing.T) {
	c := qt.New(t)

	prog, err := ebpf.NewProgram(&kprobeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	up, err := bashEx.Uprobe(bashSym, prog)
	c.Assert(err, qt.IsNil)
	defer up.Close()

	testLink(t, up, testLinkOptions{
		prog: prog,
	})
}

func TestUretprobe(t *testing.T) {
	c := qt.New(t)

	prog, err := ebpf.NewProgram(&kprobeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	up, err := bashEx.Uretprobe(bashSym, prog)
	c.Assert(err, qt.IsNil)
	defer up.Close()

	testLink(t, up, testLinkOptions{
		prog: prog,
	})
}

// Test u(ret)probe creation using perf_uprobe PMU.
func TestUprobeCreatePMU(t *testing.T) {
	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	c := qt.New(t)

	// Fetch the elf.Symbol from the /bin/bash Executable already defined.
	sym, err := bashEx.symbol(bashSym)
	c.Assert(err, qt.IsNil)

	// uprobe PMU
	pu, err := pmuUprobe(sym.Name, bashEx.path, sym.Value, false)
	c.Assert(err, qt.IsNil)
	defer pu.Close()

	c.Assert(pu.typ, qt.Equals, uprobeEvent)

	// uretprobe PMU
	pr, err := pmuUprobe(sym.Name, bashEx.path, sym.Value, true)
	c.Assert(err, qt.IsNil)
	defer pr.Close()

	c.Assert(pr.typ, qt.Equals, uretprobeEvent)
}

// Test fallback behaviour on kernels without perf_uprobe PMU available.
func TestUprobePMUUnavailable(t *testing.T) {
	c := qt.New(t)

	// Fetch the elf.Symbol from the /bin/bash Executable already defined.
	sym, err := bashEx.symbol(bashSym)
	c.Assert(err, qt.IsNil)

	pk, err := pmuUprobe(sym.Name, bashEx.path, sym.Value, false)
	if err == nil {
		pk.Close()
		t.Skipf("Kernel supports perf_uprobe PMU, not asserting error.")
	}

	// Expect ErrNotSupported.
	c.Assert(errors.Is(err, ErrNotSupported), qt.IsTrue, qt.Commentf("got error: %s", err))
}

// Test tracefs u(ret)probe creation on all kernel versions.
func TestUprobeTraceFS(t *testing.T) {
	c := qt.New(t)

	// Fetch the elf.Symbol from the /bin/bash Executable already defined.
	sym, err := bashEx.symbol(bashSym)
	c.Assert(err, qt.IsNil)

	// Sanitize the symbol in order to be used in tracefs API.
	ssym := uprobeSanitizedSymbol(sym.Name)

	// Open and close tracefs u(ret)probes, checking all errors.
	up, err := tracefsUprobe(ssym, bashEx.path, sym.Value, false)
	c.Assert(err, qt.IsNil)
	c.Assert(up.Close(), qt.IsNil)
	c.Assert(up.typ, qt.Equals, uprobeEvent)

	up, err = tracefsUprobe(ssym, bashEx.path, sym.Value, true)
	c.Assert(err, qt.IsNil)
	c.Assert(up.Close(), qt.IsNil)
	c.Assert(up.typ, qt.Equals, uretprobeEvent)

	// Create two identical trace events, ensure their IDs differ.
	u1, err := tracefsUprobe(ssym, bashEx.path, sym.Value, false)
	c.Assert(err, qt.IsNil)
	defer u1.Close()
	c.Assert(u1.tracefsID, qt.Not(qt.Equals), 0)

	u2, err := tracefsUprobe(ssym, bashEx.path, sym.Value, false)
	c.Assert(err, qt.IsNil)
	defer u2.Close()
	c.Assert(u2.tracefsID, qt.Not(qt.Equals), 0)

	// Compare the uprobes' tracefs IDs.
	c.Assert(u1.tracefsID, qt.Not(qt.CmpEquals()), u2.tracefsID)
}

// Test u(ret)probe creation writing directly to <tracefs>/uprobe_events.
// Only runs on 5.0 and over. Earlier versions ignored writes of duplicate
// events, while 5.0 started returning -EEXIST when a uprobe event already
// exists.
func TestUprobeCreateTraceFS(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "<tracefs>/uprobe_events doesn't reject duplicate events")

	c := qt.New(t)

	// Fetch the elf.Symbol from the /bin/bash Executable already defined.
	sym, err := bashEx.symbol(bashSym)
	c.Assert(err, qt.IsNil)

	// Sanitize the symbol in order to be used in tracefs API.
	ssym := uprobeSanitizedSymbol(sym.Name)

	pg, _ := randomGroup("ebpftest")
	rg, _ := randomGroup("ebpftest")

	// Tee up cleanups in case any of the Asserts abort the function.
	defer func() {
		_ = closeTraceFSProbeEvent(uprobeType, pg, ssym)
		_ = closeTraceFSProbeEvent(uprobeType, rg, ssym)
	}()

	// Create a uprobe.
	err = createTraceFSProbeEvent(uprobeType, pg, ssym, bashEx.path, sym.Value, false)
	c.Assert(err, qt.IsNil)

	// Attempt to create an identical uprobe using tracefs,
	// expect it to fail with os.ErrExist.
	err = createTraceFSProbeEvent(uprobeType, pg, ssym, bashEx.path, sym.Value, false)
	c.Assert(errors.Is(err, os.ErrExist), qt.IsTrue,
		qt.Commentf("expected consecutive uprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the kprobe.
	c.Assert(closeTraceFSProbeEvent(uprobeType, pg, ssym), qt.IsNil)

	// Same test for a kretprobe.
	err = createTraceFSProbeEvent(uprobeType, rg, ssym, bashEx.path, sym.Value, true)
	c.Assert(err, qt.IsNil)

	err = createTraceFSProbeEvent(uprobeType, rg, ssym, bashEx.path, sym.Value, true)
	c.Assert(os.IsExist(err), qt.IsFalse,
		qt.Commentf("expected consecutive uretprobe creation to contain os.ErrExist, got: %v", err))

	// Expect a successful close of the uretprobe.
	c.Assert(closeTraceFSProbeEvent(uprobeType, rg, ssym), qt.IsNil)
}

func TestUprobeSanitizedSymbol(t *testing.T) {
	var tests = []struct {
		symbol   string
		expected string
	}{
		{"readline", "readline"},
		{"main.Func", "main_Func"},
		{"a.....a", "a_a"},
		{"./;'{}[]a", "_a"},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			sanitized := uprobeSanitizedSymbol(tt.symbol)
			if tt.expected != sanitized {
				t.Errorf("Expected sanitized symbol to be '%s', got '%s'", tt.expected, sanitized)
			}
		})
	}
}

func TestUprobePathOffset(t *testing.T) {
	var tests = []struct {
		path     string
		offset   uint64
		expected string
	}{
		{"/bin/bash", 0, "/bin/bash:0x0"},
		{"/bin/bash", 1, "/bin/bash:0x1"},
		{"/bin/bash", 65535, "/bin/bash:0xffff"},
		{"/bin/bash", 65536, "/bin/bash:0x10000"},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			po := uprobePathOffset(tt.path, tt.offset)
			if tt.expected != po {
				t.Errorf("Expected path:offset to be '%s', got '%s'", tt.expected, po)
			}
		})
	}
}

func TestUprobeProgramCall(t *testing.T) {
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
	p := newMapUpdaterProg(t, m, ebpf.Kprobe)

	// Open Uprobe on '/bin/bash' for the symbol 'main'
	// and attach it to the ebpf program created above.
	u, err := bashEx.Uprobe(bashSym, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func(l Link) {
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}(u)

	// Trigger ebpf program call.
	_ := exec.Command("/bin/bash", "42").Run()

	// Assert that the value has been updated to 1.
	var val uint32
	if err := m.Lookup(uint32(0), &val); err != nil {
		t.Fatal(err)
	}
	if val != 1 {
		t.Fatalf("unexpected value: want '1', got '%d'", val)
	}
}
