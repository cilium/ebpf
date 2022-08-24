package features

import (
	"errors"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
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
	ebpf.StructOpsMap:        "5.6",
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
			testutils.SkipOnOldKernel(t, minVersion, feature)

			if err := HaveMapType(mt); err != nil {
				t.Fatalf("Map type %s isn't supported even though kernel is at least %s: %v", mt.String(), minVersion, err)
			}
		})
	}
}

type haveMapFlagsTestEntry struct {
	flags            MapFlags
	minKernelVersion string
	description      string
}

func TestHaveMapFlag(t *testing.T) {
	mapFlagTestEntries := []haveMapFlagsTestEntry{
		{BPF_F_RDONLY_PROG, "5.2", "read_only_array_map"},
		{BPF_F_WRONLY_PROG, "5.2", "write_only_array_map"},
		{BPF_F_MMAPABLE, "5.5", "mmapable_array_map"},
		{BPF_F_INNER_MAP, "5.10", "inner_map_array_map"},
		{BPF_F_NO_PREALLOC, "4.6", "no_prealloc_hash_map"},
	}

	for _, entry := range mapFlagTestEntries {
		t.Run(entry.description, func(t *testing.T) {
			err := HaveMapFlag(entry.flags)
			if testutils.IsKernelLessThan(t, entry.minKernelVersion) {
				if err == nil {
					t.Fatalf("Map flag %d is supported on this kernel even though kernel is less than %s", entry.flags, entry.minKernelVersion)
				}
			} else {
				if err != nil {
					t.Fatalf("Map flag %d isn't supported even though kernel is at least %s: %v", entry.flags, entry.minKernelVersion, err)
				}
			}
		})
	}
}

func TestHaveMapTypeUnsupported(t *testing.T) {
	if err := haveMapType(ebpf.MapType(math.MaxUint32)); !errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatalf("Expected ebpf.ErrNotSupported but was: %v", err)
	}
}

func TestHaveMapTypeInvalid(t *testing.T) {
	if err := HaveMapType(ebpf.MapType(math.MaxUint32)); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Expected os.ErrInvalid but was: %v", err)
	}
}
