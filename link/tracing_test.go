package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestFreplace(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.10", "freplace")

	testutils.Files(t, testutils.Glob(t, "../testdata/freplace-*.elf"), func(t *testing.T, file string) {
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
		}

		target, err := ebpf.NewProgram(spec.Programs["sched_process_exec"])
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create target program:", err)
		}
		defer target.Close()

		// Test attachment specified at load time
		spec.Programs["replacement"].AttachTarget = target
		replacement, err := ebpf.NewProgram(spec.Programs["replacement"])
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create replacement program:", err)
		}
		defer replacement.Close()

		freplace, err := AttachFreplace(nil, "", replacement)
		if err != nil {
			t.Fatal("Can't create freplace:", err)
		}

		testLink(t, freplace, testLinkOptions{
			prog: replacement,
			loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
				return LoadPinnedFreplace(s, opts)
			},
		})
	})
}
