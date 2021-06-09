package features

import (
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

// IsOldKernel checks whether the current kernel version is older than the provide minVersion.
// We can move it to testutils and use it with the SkipOnOldKernel function while keeping it exported
// for tests that want to run on old kernels?
func IsOldKernel(t *testing.T, minVersion string) bool {
	minV, err := internal.NewVersion(minVersion)
	if err != nil {
		t.Fatal(err)
	}

	kVersion, err := internal.KernelVersion()
	if err != nil {
		t.Fatal(err)
	}

	if kVersion.Less(minV) {
		return true
	}

	return false
}

type testCase struct {
	mapType    ebpf.MapType
	minVersion string
}

var testCases = []testCase{
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

func TestHaveMapType(t *testing.T) {
	for _, tc := range testCases {
		feature := fmt.Sprintf("map type %s", tc.mapType.String())

		t.Run(tc.mapType.String(), func(t *testing.T) {
			testutils.SkipOnOldKernel(t, tc.minVersion, feature)

			if err := HaveMapType(tc.mapType); err != nil {
				t.Fatalf("map type %s isn't supported even though kernel is at least %s: %v", tc.mapType.String(), tc.minVersion, err)
			}
		})

	}

}

func TestHaveMapTypeUnsupported(t *testing.T) {
	for _, tc := range testCases {
		feature := fmt.Sprintf("map type %s", tc.mapType.String())

		t.Run(tc.mapType.String(), func(t *testing.T) {
			if !IsOldKernel(t, tc.minVersion) {
				t.Skipf("Test requires a kernel less than %s (due to missing %s)", tc.minVersion, feature)
			}

			if err := HaveMapType(tc.mapType); err != ebpf.ErrNotSupported {
				if err != nil {
					t.Fatalf("probe for map type %s failed: %v", tc.mapType.String(), err)
				}
				t.Fatalf("map type %s shouldn't be supported because kernel is less than %s", tc.mapType.String(), tc.minVersion)
			}
		})

	}

}

func TestHaveMapTypeInvalid(t *testing.T) {
	if err := HaveMapType(ebpf.MapType(math.MaxUint32)); err != os.ErrInvalid {
		t.Fatal(err)
	}
}
