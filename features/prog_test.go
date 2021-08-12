package features

import (
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
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
