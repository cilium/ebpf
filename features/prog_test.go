package features

import (
	"fmt"
	"math"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveProgramType(t *testing.T) {
	cache := btf.NewCache()
	testCases := []struct {
		progType ebpf.ProgramType
		version  string
	}{
		{ebpf.SocketFilter, "3.19"},
		{ebpf.Kprobe, "4.1"},
		{ebpf.SchedCLS, "4.1"},
		{ebpf.SchedACT, "4.1"},
		{ebpf.TracePoint, "4.7"},
		{ebpf.XDP, "4.8"},
		{ebpf.PerfEvent, "4.9"},
		{ebpf.CGroupSKB, "4.10"},
		{ebpf.CGroupSock, "4.10"},
		{ebpf.LWTIn, "4.10"},
		{ebpf.LWTOut, "4.10"},
		{ebpf.LWTXmit, "4.10"},
		{ebpf.SockOps, "4.13"},
		{ebpf.SkSKB, "4.14"},
		{ebpf.CGroupDevice, "4.15"},
		{ebpf.SkMsg, "4.17"},
		{ebpf.RawTracepoint, "4.17"},
		{ebpf.CGroupSockAddr, "4.17"},
		{ebpf.LWTSeg6Local, "4.18"},
		{ebpf.LircMode2, "4.18"},
		{ebpf.SkReuseport, "4.19"},
		{ebpf.FlowDissector, "4.20"},
		{ebpf.CGroupSysctl, "5.2"},
		{ebpf.RawTracepointWritable, "5.2"},
		{ebpf.CGroupSockopt, "5.3"},
		{ebpf.Tracing, "5.5"},
		{ebpf.StructOps, "5.6"},
		{ebpf.Extension, "5.6"},
		{ebpf.LSM, "5.7"},
		{ebpf.SkLookup, "5.9"},
		{ebpf.Syscall, "5.14"},
		{ebpf.Netfilter, "6.4"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.progType.String(), func(t *testing.T) {
			testutils.SkipOnOldKernel(t, testCase.version, testCase.progType.String())

			err := HaveProgramType(cache, testCase.progType)
			testutils.SkipIfNotSupportedOnOS(t, err)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHaveProgramTypeInvalid(t *testing.T) {
	cache := btf.NewCache()
	if err := HaveProgramType(cache, ebpf.ProgramType(math.MaxUint32)); err == nil {
		t.Fatal("Expected an error")
	}
}

func TestHaveProgramHelper(t *testing.T) {
	type testCase struct {
		helper  asm.BuiltinFunc
		version string
	}

	// Referencing linux kernel commits to track the kernel version required to pass these test cases.
	// These cases are derived from libbpf's selftests and helper/prog combinations that are
	// probed for in cilium/cilium.
	testCases := []testCase{
		{asm.FnMapLookupElem, "3.19"},     // d0003ec01c66
		{asm.FnKtimeGetCoarseNs, "5.11"},  // d05512618056
		{asm.FnSkbVlanPush, "4.3"},        // 4e10df9a60d9
		{asm.FnSysBpf, "5.14"},            // 79a7f8bdb159
		{asm.FnJiffies64, "5.5"},          // 5576b991e9c1
		{asm.FnKtimeGetBootNs, "5.7"},     // 71d19214776e
		{asm.FnSkbChangeHead, "5.8"},      // 6f3f65d80dac
		{asm.FnRedirectNeigh, "5.10"},     // b4ab31414970
		{asm.FnSkbEcnSetCe, "5.1"},        // f7c917ba11a6
		{asm.FnSkAssign, "5.6"},           // cf7fbe660f2d
		{asm.FnFibLookup, "4.18"},         // 87f5fc7e48dd
		{asm.FnGetsockopt, "5.8"},         // beecf11bc218
		{asm.FnSkLookupTcp, "4.20"},       // 6acc9b432e67
		{asm.FnGetNetnsCookie, "5.7"},     // f318903c0bf4
		{asm.FnGetCgroupClassid, "5.7"},   // 5a52ae4e32a6
		{asm.FnGetBranchSnapshot, "5.16"}, // 856c02dbce4f
		{asm.FnSkbSetTstamp, "5.18"},      // 9bb984f28d5b
		{asm.FnSkStorageDelete, "5.3"},    // 6ac99e8f23d4
		{asm.FnSkcToUdp6Sock, "5.9"},      // 0d4fad3e57df
		{asm.FnSysClose, "5.14"},          // 3abea089246f
		{asm.FnCgrpStorageDelete, "6.4"},  // c4bcfb38a95e
	}

	cache := btf.NewCache()
	for _, tc := range testCases {
		t.Run(tc.helper.String(), func(t *testing.T) {
			feature := fmt.Sprintf("helper %s", tc.helper.String())

			testutils.SkipOnOldKernel(t, tc.version, feature)

			err := HaveProgramHelper(cache, tc.helper)
			testutils.SkipIfNotSupportedOnOS(t, err)
			if err != nil {
				t.Fatalf("%s: %v", tc.helper.String(), err)
			}

		})

	}
}
