package features

import (
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

var mapTypeMinVersion = map[ebpf.MapType]string{
	ebpf.Hash:                "3.19",
	ebpf.Array:               "3.19",
	ebpf.ProgramArray:        "4.2",
	ebpf.PerfEventArray:      "4.3",
	ebpf.PerCPUHash:          "4.6",
	ebpf.PerCPUArray:         "4.6",
	ebpf.StackTrace:          "4.6",
	ebpf.CGroupArray:         "4.8",
	ebpf.LRUHash:             "4.10",
	ebpf.LRUCPUHash:          "4.10",
	ebpf.LPMTrie:             "4.11",
	ebpf.ArrayOfMaps:         "4.12",
	ebpf.HashOfMaps:          "4.12",
	ebpf.DevMap:              "4.14",
	ebpf.SockMap:             "4.14",
	ebpf.CPUMap:              "4.15",
	ebpf.XSKMap:              "4.18",
	ebpf.SockHash:            "4.18",
	ebpf.CGroupStorage:       "4.19",
	ebpf.ReusePortSockArray:  "4.19",
	ebpf.PerCPUCGroupStorage: "4.20",
	ebpf.Queue:               "4.20",
	ebpf.Stack:               "4.20",
	ebpf.SkStorage:           "5.2",
	ebpf.DevMapHash:          "5.4",
	ebpf.StructOpsMap:        "5.6", // requires vmlinux BTF, skip for now
	ebpf.RingBuf:             "5.8",
	ebpf.InodeStorage:        "5.10",
	ebpf.TaskStorage:         "5.11",
}

func TestHaveMapType(t *testing.T) {
	for mt := ebpf.UnspecifiedMap + 1; mt <= mt.Max(); mt++ {
		minVersion, ok := mapTypeMinVersion[mt]
		if !ok {
			// In cases were a new map type wasn't added to testCases
			// we should make sure the test runs anyway and fails on old kernels
			minVersion = "0.0"
		}

		feature := fmt.Sprintf("map type %s", mt.String())

		t.Run(mt.String(), func(t *testing.T) {
			if mt == ebpf.StructOpsMap {
				t.Skip("Test for map type StructOpsMap requires working probe")
			}

			testutils.SkipOnOldKernel(t, minVersion, feature)

			if err := HaveMapType(mt); err != nil {
				t.Fatalf("Map type %s isn't supported even though kernel is at least %s: %v", mt.String(), minVersion, err)
			}
		})
	}
}

var mapFlagMinVersion = map[mapFlagCacheEntry]string{
	{ebpf.Array, unix.BPF_F_MMAPABLE}: "5.5",
}

func TestHaveMapFlags(t *testing.T) {
	for entry, minVersion := range mapFlagMinVersion {
		feature := fmt.Sprintf("%s:%d", entry.mt.String(), entry.flags)

		t.Run(feature, func(t *testing.T) {
			err := HaveMapFlags(entry.mt, entry.flags)
			if testutils.IsKernelLessThan(t, minVersion) {
				if err == nil {
					t.Fatalf("Map type %s and flags %d are supported on this kernel even though kernel is less than %s", entry.mt.String(), entry.flags, minVersion)
				}
			} else {
				if err != nil {
					t.Fatalf("Map type %s and flags %d aren't supported even though kernel is at least %s: %v", entry.mt.String(), entry.flags, minVersion, err)
				}
			}
		})
	}
}

func TestHaveMapTypeUnsupported(t *testing.T) {
	if err := haveMapType(ebpf.MapType(math.MaxUint32)); err != ebpf.ErrNotSupported {
		t.Fatalf("Expected ebpf.ErrNotSupported but was: %v", err)
	}
}

func TestHaveMapTypeInvalid(t *testing.T) {
	if err := HaveMapType(ebpf.MapType(math.MaxUint32)); err != os.ErrInvalid {
		t.Fatalf("Expected os.ErrInvalid but was: %v", err)
	}

	if err := HaveMapType(ebpf.MapType(ebpf.StructOpsMap)); err == nil {
		t.Fatal("Expected but was nil")
	}
}
