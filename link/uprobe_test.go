//go:build !windows

package link

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/tracefs"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	// Functions in testdata/uprobe.c. Only the first one returns to its caller.
	uprobeSyms = []string{"uprobe_returns", "uprobe_exits", "_start"}
	uprobeSym  = uprobeSyms[0]
)

// uprobeTarget opens the prebuilt executable from testdata/uprobe.c.
func uprobeTarget(tb testing.TB) *Executable {
	tb.Helper()

	// The kernel reports absolute paths in link info.
	path, err := filepath.Abs(fmt.Sprintf("../testdata/uprobe-%s.elf", runtime.GOARCH))
	qt.Assert(tb, qt.IsNil(err))

	ex, err := OpenExecutable(path)
	if errors.Is(err, os.ErrNotExist) {
		tb.Skipf("No uprobe target binary for %s", runtime.GOARCH)
	}
	qt.Assert(tb, qt.IsNil(err))

	return ex
}

func runTarget(tb testing.TB, ex *Executable) {
	tb.Helper()

	qt.Assert(tb, qt.IsNil(exec.Command(ex.path).Run()))
}

func TestExecutable(t *testing.T) {
	_, err := OpenExecutable("")
	qt.Assert(t, qt.IsNotNil(err))

	_, err = OpenExecutable("/non/existent/path")
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	var pe *os.PathError
	qt.Assert(t, qt.ErrorAs(err, &pe))

	// create temp non-executable file
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("hello"), 0600)))

	_, err = OpenExecutable(path)
	qt.Assert(t, qt.IsNil(err))

	// make it executable
	err = os.Chmod(path, 0700)
	qt.Assert(t, qt.IsNil(err))

	_, err = OpenExecutable(path)
	qt.Assert(t, qt.IsNil(err))

	ex := uprobeTarget(t)
	_, err = ex.address(uprobeSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	_, err = ex.address("bogus", 0, 0)
	qt.Assert(t, qt.IsNotNil(err))
}

func TestExecutableOffset(t *testing.T) {
	ex := uprobeTarget(t)

	symbolOffset, err := ex.address(uprobeSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	offset, err := ex.address(uprobeSym, 0x1, 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(offset, 0x1))

	offset, err = ex.address(uprobeSym, 0, 0x2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(offset, symbolOffset+0x2))

	offset, err = ex.address(uprobeSym, 0x1, 0x2)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(offset, 0x1+0x2))
}

func TestExecutableLazyLoadSymbols(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex := uprobeTarget(t)
	// Addresses must be empty, will be lazy loaded.
	qt.Assert(t, qt.HasLen(ex.cachedSymbols, 0))

	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")
	// Address must be a multiple of 4 on arm64, see
	// https://elixir.bootlin.com/linux/v6.6.4/source/arch/arm64/kernel/probes/uprobes.c#L42
	up, err := ex.Uprobe(uprobeSym, prog, &UprobeOptions{Address: 124})
	qt.Assert(t, qt.IsNil(err))
	up.Close()

	// Addresses must still be empty as Address has been provided via options.
	qt.Assert(t, qt.HasLen(ex.cachedSymbols, 0))

	up, err = ex.Uprobe(uprobeSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	up.Close()

	// Symbol table should be loaded.
	qt.Assert(t, qt.Not(qt.HasLen(ex.cachedSymbols, 0)))
}

func TestUprobe(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := ex.Uprobe(uprobeSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()

	testLink(t, up, prog)
}

func TestUprobeInfo(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "bpf_link_info_perf_event")

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := ex.Uprobe(uprobeSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()

	info, err := up.Info()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(info.Type, PerfEventType))
	eventInfo := info.PerfEvent()
	qt.Assert(t, qt.Equals(eventInfo.Type, PerfEventUprobe))
	uprobeInfo := eventInfo.Uprobe()
	qt.Assert(t, qt.StringContains(uprobeInfo.File, ex.path))
	executable, err := OpenExecutable(uprobeInfo.File)
	qt.Assert(t, qt.IsNil(err))
	sym, err := executable.Symbol(uint64(uprobeInfo.Offset))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sym.Symbol, uprobeSym))
	qt.Assert(t, qt.Equals(sym.Offset, 0))
}

func TestUprobeExtNotFound(t *testing.T) {
	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// This symbol will not be present in Executable (elf.SHN_UNDEF).
	_, err := ex.Uprobe("open", prog, nil)
	qt.Assert(t, qt.IsNotNil(err))
}

func TestUprobeExtWithOpts(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// NB: It's not possible to invoke the uprobe since we use an arbitrary
	// address.
	up, err := ex.Uprobe("open", prog, &UprobeOptions{
		// arm64 requires the addresses to be aligned (a multiple of 4)
		Address: 0x4,
	})
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()
}

func TestUprobeWithPID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := ex.Uprobe(uprobeSym, prog, &UprobeOptions{PID: os.Getpid()})
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()
}

func TestUprobeWithNonExistentPID(t *testing.T) {
	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	// trying to open a perf event on a non-existent PID will return ESRCH.
	_, err := ex.Uprobe(uprobeSym, prog, &UprobeOptions{PID: -2})
	qt.Assert(t, qt.ErrorIs(err, unix.ESRCH))
}

func TestUretprobe(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")

	up, err := ex.Uretprobe(uprobeSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer up.Close()

	testLink(t, up, prog)
}

// Test u(ret)probe creation using perf_uprobe PMU.
func TestUprobeCreatePMU(t *testing.T) {
	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	ex := uprobeTarget(t)
	off, err := ex.address(uprobeSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	// Prepare probe args.
	args := tracefs.ProbeArgs{
		Type:   tracefs.Uprobe,
		Symbol: uprobeSym,
		Path:   ex.path,
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
	ex := uprobeTarget(t)
	off, err := ex.address(uprobeSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	// Prepare probe args.
	args := tracefs.ProbeArgs{
		Type:   tracefs.Uprobe,
		Symbol: uprobeSym,
		Path:   ex.path,
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

	ex := uprobeTarget(t)
	off, err := ex.address(uprobeSym, 0, 0)
	qt.Assert(t, qt.IsNil(err))

	// Prepare probe args.
	args := tracefs.ProbeArgs{
		Type:   tracefs.Uprobe,
		Symbol: uprobeSym,
		Path:   ex.path,
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

	ex := uprobeTarget(t)
	m, p := newUpdaterMapProg(t, ebpf.Kprobe, 0)

	u, err := ex.Uprobe(uprobeSym, p, nil)
	qt.Assert(t, qt.IsNil(err))

	runTarget(t, ex)

	// Assert that the value got incremented to at least 1, while allowing
	// for bigger values, because we could race with other test binaries.
	assertMapValueGE(t, m, 0, 1)

	// Detach the Uprobe.
	qt.Assert(t, qt.IsNil(u.Close()))

	// Reset map value to 0 at index 0.
	qt.Assert(t, qt.IsNil(m.Update(uint32(0), uint32(0), ebpf.UpdateExist)))

	runTarget(t, ex)

	// Assert that this time the value has not been updated.
	assertMapValue(t, m, 0, 0)
}

func TestUprobeProgramWrongPID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.14", "uprobe on v4.9 returns EIO on vimto")

	ex := uprobeTarget(t)
	m, p := newUpdaterMapProg(t, ebpf.Kprobe, 0)

	// Create the perf-event with the current process' PID
	// to make sure the event is not fired when we will try
	// to trigger the program execution via exec.
	u, err := ex.Uprobe(uprobeSym, p, &UprobeOptions{PID: os.Getpid()})
	qt.Assert(t, qt.IsNil(err))
	defer u.Close()

	runTarget(t, ex)

	// Assert that the value at index 0 is still 0.
	assertMapValue(t, m, 0, 0)
}

func TestHaveRefCtrOffsetPMU(t *testing.T) {
	testutils.CheckFeatureTest(t, haveRefCtrOffsetPMU)
}
