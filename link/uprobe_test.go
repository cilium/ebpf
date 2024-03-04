package link

import (
	"errors"
	"go/build"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/tracefs"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	bashEx, _ = OpenExecutable("/bin/bash")
	bashSyms  = []string{"main", "_start", "check_dev_tty"}
	bashSym   = bashSyms[0]
)

func TestExecutable(t *testing.T) {
	_, err := OpenExecutable("")
	if err == nil {
		t.Fatal("create executable: expected error on empty path")
	}

	if bashEx.path != "/bin/bash" {
		t.Fatalf("create executable: unexpected path '%s'", bashEx.path)
	}

	_, err = bashEx.address(bashSym, 0, 0)
	if err != nil {
		t.Fatalf("find offset: %v", err)
	}

	_, err = bashEx.address("bogus", 0, 0)
	if err == nil {
		t.Fatal("find symbol: expected error")
	}
}

func TestExecutableOffset(t *testing.T) {
	symbolOffset, err := bashEx.address(bashSym, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	offset, err := bashEx.address(bashSym, 0x1, 0)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(offset, 0x1))

	offset, err = bashEx.address(bashSym, 0, 0x2)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(offset, symbolOffset+0x2))

	offset, err = bashEx.address(bashSym, 0x1, 0x2)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(offset, 0x1+0x2))
}

func TestExecutableLazyLoadSymbols(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex, err := OpenExecutable("/bin/bash")
	qt.Assert(t, qt.IsNil(err))
	// Addresses must be empty, will be lazy loaded.
	qt.Assert(t, qt.HasLen(ex.cachedAddresses, 0))

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")
	// Address must be a multiple of 4 on arm64, see
	// https://elixir.bootlin.com/linux/v6.6.4/source/arch/arm64/kernel/probes/uprobes.c#L42
	up, err := ex.Uprobe(bashSym, prog, &UprobeOptions{Address: 124})
	qt.Assert(t, qt.IsNil(err))
	up.Close()

	// Addresses must still be empty as Address has been provided via options.
	qt.Assert(t, qt.HasLen(ex.cachedAddresses, 0))

	up, err = ex.Uprobe(bashSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	up.Close()

	// Symbol table should be loaded.
	qt.Assert(t, qt.Not(qt.HasLen(ex.cachedAddresses, 0)))
}

func TestUprobe(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := bashEx.Uprobe(bashSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()

	testLink(t, up, prog)
}

func TestUprobeExtNotFound(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// This symbol will not be present in Executable (elf.SHN_UNDEF).
	_, err := bashEx.Uprobe("open", prog, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUprobeExtWithOpts(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// NB: It's not possible to invoke the uprobe since we use an arbitrary
	// address.
	up, err := bashEx.Uprobe("open", prog, &UprobeOptions{
		// arm64 requires the addresses to be aligned (a multiple of 4)
		Address: 0x4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
}

func TestUprobeWithPID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := bashEx.Uprobe(bashSym, prog, &UprobeOptions{PID: os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
}

func TestUprobeWithNonExistentPID(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// trying to open a perf event on a non-existent PID will return ESRCH.
	_, err := bashEx.Uprobe(bashSym, prog, &UprobeOptions{PID: -2})
	if !errors.Is(err, unix.ESRCH) {
		t.Fatalf("expected ESRCH, got %v", err)
	}
}

func TestUretprobe(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := bashEx.Uretprobe(bashSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()

	testLink(t, up, prog)
}

// Test u(ret)probe creation using perf_uprobe PMU.
func TestUprobeCreatePMU(t *testing.T) {
	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	// Fetch the offset from the /bin/bash Executable already defined.
	off, err := bashEx.address(bashSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	// Prepare probe args.
	args := tracefs.ProbeArgs{
		Type:   tracefs.Uprobe,
		Symbol: bashSym,
		Path:   bashEx.path,
		Offset: off,
		Pid:    perfAllThreads,
	}

	// uprobe PMU
	pu, err := pmuProbe(args)
	qt.Assert(t, qt.IsNil(err))
	defer pu.Close()

	// uretprobe PMU
	args.Ret = true
	pr, err := pmuProbe(args)
	qt.Assert(t, qt.IsNil(err))
	defer pr.Close()
}

// Test fallback behaviour on kernels without perf_uprobe PMU available.
func TestUprobePMUUnavailable(t *testing.T) {
	// Fetch the offset from the /bin/bash Executable already defined.
	off, err := bashEx.address(bashSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	// Prepare probe args.
	args := tracefs.ProbeArgs{
		Type:   tracefs.Uprobe,
		Symbol: bashSym,
		Path:   bashEx.path,
		Offset: off,
		Pid:    perfAllThreads,
	}

	pk, err := pmuProbe(args)
	if err == nil {
		pk.Close()
		t.Skipf("Kernel supports perf_uprobe PMU, not asserting error.")
	}

	// Expect ErrNotSupported.
	qt.Assert(t, qt.ErrorIs(err, ErrNotSupported), qt.Commentf("got error: %s", err))
}

// Test tracefs u(ret)probe creation on all kernel versions.
func TestUprobeTraceFS(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	// Fetch the offset from the /bin/bash Executable already defined.
	off, err := bashEx.address(bashSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	// Prepare probe args.
	args := tracefs.ProbeArgs{
		Type:   tracefs.Uprobe,
		Symbol: bashSym,
		Path:   bashEx.path,
		Offset: off,
		Pid:    perfAllThreads,
	}

	// Open and close tracefs u(ret)probes, checking all errors.
	up, err := tracefsProbe(args)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(up.Close()))

	args.Ret = true
	up, err = tracefsProbe(args)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(up.Close()))

	// Create two identical trace events, ensure their IDs differ.
	args.Ret = false
	u1, err := tracefsProbe(args)
	qt.Assert(t, qt.IsNil(err))
	defer u1.Close()
	qt.Assert(t, qt.IsNotNil(u1.tracefsEvent))

	u2, err := tracefsProbe(args)
	qt.Assert(t, qt.IsNil(err))
	defer u2.Close()
	qt.Assert(t, qt.IsNotNil(u2.tracefsEvent))

	// Compare the uprobes' tracefs IDs.
	qt.Assert(t, qt.Not(qt.Equals(u1.tracefsEvent.ID(), u2.tracefsEvent.ID())))

	// Expect an error when supplying an invalid custom group name
	args.Group = "/"
	_, err = tracefsProbe(args)
	qt.Assert(t, qt.Not(qt.IsNil(err)))

	args.Group = "customgroup"
	u3, err := tracefsProbe(args)
	qt.Assert(t, qt.IsNil(err))
	defer u3.Close()
	qt.Assert(t, qt.Matches(u3.tracefsEvent.Group(), `customgroup_[a-f0-9]{16}`))
}

func TestUprobeProgramCall(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	tests := []struct {
		name string
		elf  string
		args []string
		sym  string
	}{
		{
			"bash",
			"/bin/bash",
			[]string{"--help"},
			"main",
		},
		{
			"go-binary",
			path.Join(build.Default.GOROOT, "bin/go"),
			[]string{"version"},
			"main.main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "go-binary" {
				// https://github.com/cilium/ebpf/issues/406
				testutils.SkipOnOldKernel(t, "4.14", "uprobes on Go binaries silently fail on kernel < 4.14")
			}

			m, p := newUpdaterMapProg(t, ebpf.Kprobe, 0)

			// Load the executable.
			ex, err := OpenExecutable(tt.elf)
			if err != nil {
				t.Fatal(err)
			}

			// Open Uprobe on the executable for the given symbol
			// and attach it to the ebpf program created above.
			u, err := ex.Uprobe(tt.sym, p, nil)
			if errors.Is(err, ErrNoSymbol) {
				// Assume bash::main and go::main.main always exists
				// and skip the test if the symbol can't be found as
				// certain OS (eg. Debian) strip binaries.
				t.Skipf("executable %s appear to be stripped, skipping", tt.elf)
			}
			if err != nil {
				t.Fatal(err)
			}

			// Trigger ebpf program call.
			trigger := func(t *testing.T) {
				if err := exec.Command(tt.elf, tt.args...).Run(); err != nil {
					t.Fatal(err)
				}
			}
			trigger(t)

			// Assert that the value got incremented to at least 1, while allowing
			// for bigger values, because we could race with other bash execution.
			assertMapValueGE(t, m, 0, 1)

			// Detach the Uprobe.
			if err := u.Close(); err != nil {
				t.Fatal(err)
			}

			// Reset map value to 0 at index 0.
			if err := m.Update(uint32(0), uint32(0), ebpf.UpdateExist); err != nil {
				t.Fatal(err)
			}

			// Retrigger the ebpf program call.
			trigger(t)

			// Assert that this time the value has not been updated.
			assertMapValue(t, m, 0, 0)
		})
	}
}

func TestUprobeProgramWrongPID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	m, p := newUpdaterMapProg(t, ebpf.Kprobe, 0)

	// Load the '/bin/bash' executable.
	ex, err := OpenExecutable("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}

	// Open Uprobe on '/bin/bash' for the symbol 'main'
	// and attach it to the ebpf program created above.
	// Create the perf-event with the current process' PID
	// to make sure the event is not fired when we will try
	// to trigger the program execution via exec.
	u, err := ex.Uprobe("main", p, &UprobeOptions{PID: os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	// Trigger ebpf program call.
	if err := exec.Command("/bin/bash", "--help").Run(); err != nil {
		t.Fatal(err)
	}

	// Assert that the value at index 0 is still 0.
	assertMapValue(t, m, 0, 0)
}

func TestHaveRefCtrOffsetPMU(t *testing.T) {
	testutils.CheckFeatureTest(t, haveRefCtrOffsetPMU)
}
