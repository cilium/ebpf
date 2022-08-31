package features

import (
	"errors"
	"fmt"
	"math"
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

func TestHaveProgramType(t *testing.T) {
	testutils.CheckFeatureMatrix(t, haveProgramTypeMatrix)
}

func TestHaveProgramTypeInvalid(t *testing.T) {
	if err := HaveProgramType(ebpf.ProgramType(math.MaxUint32)); err == nil {
		t.Fatal("Expected an error")
	} else if errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Got ErrNotSupported:", err)
	}
}

func TestHaveProgramHelper(t *testing.T) {
	type testCase struct {
		prog     ebpf.ProgramType
		helper   asm.BuiltinFunc
		expected error
		version  string
	}

	// Referencing linux kernel commits to track the kernel version required to pass these test cases.
	// They cases are derived from libbpf's selftests and helper/prog combinations that are
	// probed for in cilium/cilium.
	// Still missing since those helpers are not available in the lib yet, are:
	// - Kprobe, GetBranchSnapshot
	// - SchedCLS, SkbSetTstamp
	// These two test cases depend on CI kernels supporting those:
	// {ebpf.Kprobe, asm.FnKtimeGetCoarseNs, ebpf.ErrNotSupported, "5.16"}, // 5e0bc3082e2e
	// {ebpf.CGroupSockAddr, asm.FnGetCgroupClassid, nil, "5.10"},    // b426ce83baa7
	testCases := []testCase{
		{ebpf.Kprobe, asm.FnMapLookupElem, nil, "3.19"},               // d0003ec01c66
		{ebpf.SocketFilter, asm.FnKtimeGetCoarseNs, nil, "5.11"},      // d05512618056
		{ebpf.SchedCLS, asm.FnSkbVlanPush, nil, "4.3"},                // 4e10df9a60d9
		{ebpf.Kprobe, asm.FnSkbVlanPush, ebpf.ErrNotSupported, "4.3"}, // 4e10df9a60d9
		{ebpf.Kprobe, asm.FnSysBpf, ebpf.ErrNotSupported, "5.14"},     // 79a7f8bdb159
		{ebpf.Syscall, asm.FnSysBpf, nil, "5.14"},                     // 79a7f8bdb159
		{ebpf.XDP, asm.FnJiffies64, nil, "5.5"},                       // 5576b991e9c1
		{ebpf.XDP, asm.FnKtimeGetBootNs, nil, "5.7"},                  // 71d19214776e
		{ebpf.SchedCLS, asm.FnSkbChangeHead, nil, "5.8"},              // 6f3f65d80dac
		{ebpf.SchedCLS, asm.FnRedirectNeigh, nil, "5.10"},             // b4ab31414970
		{ebpf.SchedCLS, asm.FnSkbEcnSetCe, nil, "5.1"},                // f7c917ba11a6
		{ebpf.SchedACT, asm.FnSkAssign, nil, "5.6"},                   // cf7fbe660f2d
		{ebpf.SchedACT, asm.FnFibLookup, nil, "4.18"},                 // 87f5fc7e48dd
		{ebpf.Kprobe, asm.FnFibLookup, ebpf.ErrNotSupported, "4.18"},  // 87f5fc7e48dd
		{ebpf.CGroupSockAddr, asm.FnGetsockopt, nil, "5.8"},           // beecf11bc218
		{ebpf.CGroupSockAddr, asm.FnSkLookupTcp, nil, "4.20"},         // 6acc9b432e67
		{ebpf.CGroupSockAddr, asm.FnGetNetnsCookie, nil, "5.7"},       // f318903c0bf4
		{ebpf.CGroupSock, asm.FnGetNetnsCookie, nil, "5.7"},           // f318903c0bf4
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

			err := HaveProgramHelper(tc.prog, tc.helper)
			if !errors.Is(err, tc.expected) {
				t.Fatalf("%s/%s: %v", tc.prog.String(), tc.helper.String(), err)
			}

		})

	}
}

func TestHaveProgramHelperUnsupported(t *testing.T) {
	pt := ebpf.SocketFilter
	minVersion := progTypeMinVersion[pt]

	feature := fmt.Sprintf("program type %s", pt.String())

	testutils.SkipOnOldKernel(t, minVersion, feature)

	if err := haveProgramHelper(pt, asm.BuiltinFunc(math.MaxInt32)); !errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatalf("Expected ebpf.ErrNotSupported but was: %v", err)
	}
}
