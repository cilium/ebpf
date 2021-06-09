package features

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

// similar as in testutils, skipTestCaseOnOldKernel helps to determine wether a testcase can be skipped
// internal.SkipOnOldKernel would skip the entire test which isn't what I want.
func skipTestCaseOnOldKernel(minVersion string) bool {
	minV, err := internal.NewVersion(minVersion)
	if err != nil {
		panic(err)
	}

	kVersion, err := internal.KernelVersion()
	if err != nil {
		panic(err)
	}

	if kVersion.Less(minV) {
		return true
	}

	return false
}

func TestHaveMapType(t *testing.T) {
	type testCase struct {
		mapType    ebpf.MapType
		minVersion string
	}

	testCases := []testCase{
		{ebpf.Hash, "3.19"},
		{ebpf.Array, "3.19"},
		{ebpf.ProgramArray, "4.2"},
		{ebpf.PerfEventArray, "4.3"},
		{ebpf.PerCPUHash, "4.6"},
		{ebpf.PerCPUArray, "4.6"},
		{ebpf.StackTrace, "4.6"},
		{ebpf.CGroupArray, "4.8"},
		{ebpf.LRUHash, "4.10"},
		{ebpf.LRUCPUHash, "4.10"},
		{ebpf.LPMTrie, "4.11"},
		{ebpf.ArrayOfMaps, "4.12"},
		{ebpf.HashOfMaps, "4.12"},
		{ebpf.DevMap, "4.14"},
		{ebpf.SockMap, "4.14"},
		{ebpf.CPUMap, "4.15"},
		{ebpf.XSKMap, "4.18"},
		{ebpf.SockHash, "4.18"},
		{ebpf.CGroupStorage, "4.19"},
		{ebpf.ReusePortSockArray, "4.19"},
		{ebpf.PerCPUCGroupStorage, "4.20"},
		{ebpf.Queue, "4.20"},
		{ebpf.Stack, "4.20"},
		{ebpf.SkStorage, "5.2"},
		{ebpf.DevMapHash, "5.4"},
		// {ebpf.StructOpts, "5.6"}, whats the best way to still test this path?
		{ebpf.RingBuf, "5.8"},
		{ebpf.InodeStorage, "5.10"},
		{ebpf.TaskStorage, "5.11"},
	}

	for _, tc := range testCases {
		if skipTestCaseOnOldKernel(tc.minVersion) {
			t.Logf("Skipped test for MapType %s: requires at least kernel version %s", tc.mapType.String(), tc.minVersion)
			continue
		}

		err := HaveMapType(tc.mapType)
		if err != nil {
			t.Fatalf("MapType %s isn't supported even though kernel is at least %s", tc.mapType.String(), tc.minVersion)
		}
	}

}
