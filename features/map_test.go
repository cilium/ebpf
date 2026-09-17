package features

import (
	"math"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveMapType(t *testing.T) {
	testCases := []struct {
		mapType ebpf.MapType
		version string
	}{
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
		{ebpf.StructOpsMap, "5.6"},
		{ebpf.RingBuf, "5.8"},
		{ebpf.InodeStorage, "5.10"},
		{ebpf.TaskStorage, "5.11"},
		{ebpf.BloomFilter, "5.16"},
		{ebpf.UserRingbuf, "6.1"},
		{ebpf.CgroupStorage, "6.2"},
		{ebpf.Arena, "6.9"},
	}

	cache := btf.NewCache()
	for _, tc := range testCases {
		t.Run(tc.mapType.String(), func(t *testing.T) {
			testutils.SkipOnOldKernel(t, tc.version, tc.mapType.String())

			err := HaveMapType(cache, tc.mapType)
			testutils.SkipIfNotSupportedOnOS(t, err)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHaveMapTypeInvalid(t *testing.T) {
	if err := HaveMapType(nil, ebpf.MapType(math.MaxUint32)); err == nil {
		t.Fatal("Expected an error")
	}
}
