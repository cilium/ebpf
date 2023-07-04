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
	"github.com/cilium/ebpf/internal/testutils/fdtrace"
)

func TestMain(m *testing.M) {
	fdtrace.TestMain(m)
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
	testCases := []testCase{
		{ebpf.Kprobe, asm.FnMapLookupElem, nil, "3.19"},                     // d0003ec01c66
		{ebpf.SocketFilter, asm.FnKtimeGetCoarseNs, nil, "5.11"},            // d05512618056
		{ebpf.SchedCLS, asm.FnSkbVlanPush, nil, "4.3"},                      // 4e10df9a60d9
		{ebpf.Kprobe, asm.FnSkbVlanPush, ebpf.ErrNotSupported, "4.3"},       // 4e10df9a60d9
		{ebpf.Kprobe, asm.FnSysBpf, ebpf.ErrNotSupported, "5.14"},           // 79a7f8bdb159
		{ebpf.Syscall, asm.FnSysBpf, nil, "5.14"},                           // 79a7f8bdb159
		{ebpf.XDP, asm.FnJiffies64, nil, "5.5"},                             // 5576b991e9c1
		{ebpf.XDP, asm.FnKtimeGetBootNs, nil, "5.7"},                        // 71d19214776e
		{ebpf.SchedCLS, asm.FnSkbChangeHead, nil, "5.8"},                    // 6f3f65d80dac
		{ebpf.SchedCLS, asm.FnRedirectNeigh, nil, "5.10"},                   // b4ab31414970
		{ebpf.SchedCLS, asm.FnSkbEcnSetCe, nil, "5.1"},                      // f7c917ba11a6
		{ebpf.SchedACT, asm.FnSkAssign, nil, "5.6"},                         // cf7fbe660f2d
		{ebpf.SchedACT, asm.FnFibLookup, nil, "4.18"},                       // 87f5fc7e48dd
		{ebpf.Kprobe, asm.FnFibLookup, ebpf.ErrNotSupported, "4.18"},        // 87f5fc7e48dd
		{ebpf.CGroupSockAddr, asm.FnGetsockopt, nil, "5.8"},                 // beecf11bc218
		{ebpf.CGroupSockAddr, asm.FnSkLookupTcp, nil, "4.20"},               // 6acc9b432e67
		{ebpf.CGroupSockAddr, asm.FnGetNetnsCookie, nil, "5.7"},             // f318903c0bf4
		{ebpf.CGroupSock, asm.FnGetNetnsCookie, nil, "5.7"},                 // f318903c0bf4
		{ebpf.Kprobe, asm.FnKtimeGetCoarseNs, ebpf.ErrNotSupported, "5.16"}, // 5e0bc3082e2e
		{ebpf.CGroupSockAddr, asm.FnGetCgroupClassid, nil, "5.7"},           // 5a52ae4e32a6
		{ebpf.Kprobe, asm.FnGetBranchSnapshot, nil, "5.16"},                 // 856c02dbce4f
		{ebpf.SchedCLS, asm.FnSkbSetTstamp, nil, "5.18"},                    // 9bb984f28d5b
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s/%s", tc.prog.String(), tc.helper.String()), func(t *testing.T) {
			feature := fmt.Sprintf("helper %s for program type %s", tc.helper.String(), tc.prog.String())

			testutils.SkipOnOldKernel(t, tc.version, feature)

			err := HaveProgramHelper(tc.prog, tc.helper)
			if !errors.Is(err, tc.expected) {
				t.Fatalf("%s/%s: %v", tc.prog.String(), tc.helper.String(), err)
			}

		})

	}
}

func TestHelperProbeNotImplemented(t *testing.T) {
	// Currently we don't support probing helpers for Tracing, Extension, LSM and StructOps programs.
	// For each of those test the availability of the FnMapLookupElem helper and expect it to fail.
	for _, pt := range []ebpf.ProgramType{ebpf.Tracing, ebpf.Extension, ebpf.LSM, ebpf.StructOps} {
		t.Run(pt.String(), func(t *testing.T) {
			if err := HaveProgramHelper(pt, asm.FnMapLookupElem); err == nil {
				t.Fatal("Expected an error")
			}
		})
	}
}
