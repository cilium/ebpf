package features

import (
	"errors"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

var progTypeMinVersion = map[ebpf.ProgramType]string{
	ebpf.SocketFilter:          "3.19",
	ebpf.Kprobe:                "4.1",
	ebpf.SchedCLS:              "4.1",
	ebpf.SchedACT:              "4.1",
	ebpf.TracePoint:            "4.7",
	ebpf.XDP:                   "4.8",
	ebpf.PerfEvent:             "4.9",
	ebpf.CGroupSKB:             "4.10",
	ebpf.CGroupSock:            "4.10",
	ebpf.LWTIn:                 "4.10",
	ebpf.LWTOut:                "4.10",
	ebpf.LWTXmit:               "4.10",
	ebpf.SockOps:               "4.13",
	ebpf.SkSKB:                 "4.14",
	ebpf.CGroupDevice:          "4.15",
	ebpf.SkMsg:                 "4.17",
	ebpf.RawTracepoint:         "4.17",
	ebpf.CGroupSockAddr:        "4.17",
	ebpf.LWTSeg6Local:          "4.18",
	ebpf.LircMode2:             "4.18",
	ebpf.SkReuseport:           "4.19",
	ebpf.FlowDissector:         "4.20",
	ebpf.CGroupSysctl:          "5.2",
	ebpf.RawTracepointWritable: "5.2",
	ebpf.CGroupSockopt:         "5.3",
	ebpf.Tracing:               "5.5",
	ebpf.StructOps:             "5.6",
	ebpf.Extension:             "5.6",
	ebpf.LSM:                   "5.7",
	ebpf.SkLookup:              "5.9",
	ebpf.Syscall:               "5.14",
}

func TestHaveProgType(t *testing.T) {
	for progType := ebpf.UnspecifiedProgram + 1; progType <= progType.Max(); progType++ {
		// Need inner loop copy to make use of t.Parallel()
		pt := progType

		minVersion, ok := progTypeMinVersion[pt]
		if !ok {
			// In cases where a new prog type wasn't added to progTypeMinVersion
			// we should make sure the test runs anyway and fails on old kernels
			minVersion = "0.0"
		}

		feature := fmt.Sprintf("program type %s", pt.String())

		t.Run(pt.String(), func(t *testing.T) {
			t.Parallel()

			if progLoadProbeNotImplemented(pt) {
				t.Skipf("Test for prog type %s requires working probe", pt.String())
			}
			testutils.SkipOnOldKernel(t, minVersion, feature)

			if err := HaveProgType(pt); err != nil {
				if pt == ebpf.LircMode2 {
					// CI kernels are built with CONFIG_BPF_LIRC_MODE2, but some
					// mainstream distro's don't ship with it. Make this prog type
					// optional to retain compatibility with those kernels.
					testutils.SkipIfNotSupported(t, err)
				}

				t.Fatalf("Program type %s isn't supported even though kernel is at least %s: %v", pt.String(), minVersion, err)
			}
		})

	}
}

func TestHaveProgTypeUnsupported(t *testing.T) {
	if err := haveProgType(ebpf.ProgramType(math.MaxUint32)); err != ebpf.ErrNotSupported {
		t.Fatalf("Expected ebpf.ErrNotSupported but was: %v", err)
	}
}

func TestHaveProgTypeInvalid(t *testing.T) {
	if err := HaveProgType(ebpf.ProgramType(math.MaxUint32)); err != os.ErrInvalid {
		t.Fatalf("Expected os.ErrInvalid but was: %v", err)
	}
}

func TestHaveProgHelper(t *testing.T) {
	type testCase struct {
		prog     ebpf.ProgramType
		helper   asm.BuiltinFunc
		expected error
		version  string
	}

	// Referecing linux kernel commits to track the kernel version required to pass these test-cases
	// These test-cases are derived from libbpf's selftests and helper/prog combinations that are
	// probed for in cilium/cilium
	// Still missing since those helpers are not available in the lib yet, are:
	// - Kprobe, GetBranchSnapshot
	// - SchedCLS, SkbSetTstamp

	testCases := []testCase{
		{ebpf.Kprobe, asm.FnMapLookupElem, nil, "3.19"},                     // @d0003ec
		{ebpf.Kprobe, asm.FnKtimeGetCoarseNs, ebpf.ErrNotSupported, "5.16"}, // @5e0bc30
		{ebpf.SocketFilter, asm.FnKtimeGetCoarseNs, nil, "5.11"},            // @d055126
		{ebpf.SchedCLS, asm.FnSkbVlanPush, nil, "4.3"},                      // @4e10df9
		{ebpf.Kprobe, asm.FnSysBpf, ebpf.ErrNotSupported, "5.14"},           // @79a7f8b
		{ebpf.Syscall, asm.FnSysBpf, nil, "5.14"},                           // @79a7f8b
		{ebpf.XDP, asm.FnJiffies64, nil, "5.5"},                             // @5576b99
		{ebpf.XDP, asm.FnKtimeGetBootNs, nil, "5.7"},                        // @71d1921
		{ebpf.SchedCLS, asm.FnSkbChangeHead, nil, "4.10"},                   // @3a0af8f
		{ebpf.SchedCLS, asm.FnRedirectNeigh, nil, "5.10"},                   // @b4ab314
		{ebpf.SchedCLS, asm.FnSkbEcnSetCe, nil, "5.1"},                      // @f7c917b
		{ebpf.SchedACT, asm.FnSkAssign, nil, "5.6"},                         // @cf7fbe6
		{ebpf.SchedACT, asm.FnFibLookup, nil, "4.18"},                       // @87f5fc7
		{ebpf.CGroupSockAddr, asm.FnGetCgroupClassid, nil, "5.10"},          // @b426ce8
		{ebpf.CGroupSockAddr, asm.FnGetsockopt, nil, "4.15"},                // @cd86d1f
		{ebpf.CGroupSockAddr, asm.FnSkLookupTcp, nil, "4.20"},               // @6acc9b4
		{ebpf.CGroupSockAddr, asm.FnGetNetnsCookie, nil, "5.7"},             // @f318903
		{ebpf.CGroupSock, asm.FnGetNetnsCookie, nil, "5.7"},                 // @f318903

	}

	for _, tc := range testCases {
		minVersion := progTypeMinVersion[tc.prog]

		progVersion, err := internal.NewVersion(minVersion)
		if err != nil {
			t.Fatalf("Could not read kernel version required for program: %v", err)
		}

		helperVersion, err := internal.NewVersion(tc.version)
		if err != nil {
			t.Fatalf("Could not read kernel version required for helper: %v", err)
		}

		if progVersion.Less(helperVersion) {
			minVersion = tc.version
		}

		t.Run(fmt.Sprintf("%s/%s", tc.prog.String(), tc.helper.String()), func(t *testing.T) {
			feature := fmt.Sprintf("helper %s for program type %s", tc.helper.String(), tc.prog.String())

			testutils.SkipOnOldKernel(t, minVersion, feature)

			err := HaveProgHelper(tc.prog, tc.helper)
			if !errors.Is(err, tc.expected) {
				t.Fatalf("%s/%s: %v", tc.prog.String(), tc.helper.String(), err)
			}

		})

	}
}

func TestHaveProgHelperUnsupported(t *testing.T) {
	pt := ebpf.SocketFilter
	minVersion := progTypeMinVersion[pt]

	feature := fmt.Sprintf("program type %s", pt.String())

	testutils.SkipOnOldKernel(t, minVersion, feature)

	if err := haveProgHelper(pt, asm.BuiltinFunc(math.MaxInt32)); err != ebpf.ErrNotSupported {
		t.Fatalf("Expected ebpf.ErrNotSupported but was: %v", err)
	}
}
