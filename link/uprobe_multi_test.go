//go:build !windows

package link

import (
	"math"
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestUprobeMulti(t *testing.T) {
	testutils.SkipIfNotSupported(t, features.HaveBPFLinkUprobeMulti())

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// uprobe
	um, err := ex.UprobeMulti(uprobeSyms, prog, nil)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, um, prog)
	_ = um.Close()

	// uretprobe
	um, err = ex.UretprobeMulti(uprobeSyms, prog, nil)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, um, prog)
	_ = um.Close()
}

func TestUprobeMultiInfo(t *testing.T) {
	testutils.SkipIfNotSupported(t, features.HaveBPFLinkUprobeMulti())
	testutils.SkipOnOldKernel(t, "6.8", "bpf_link_info_uprobe_multi")

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// uprobe
	um, err := ex.UprobeMulti(uprobeSyms, prog, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer um.Close()

	linkInfo, err := um.Info()
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(linkInfo.Type, UprobeMultiType))
	uprobeDetails := linkInfo.UprobeMulti()
	qt.Assert(t, qt.StringContains(uprobeDetails.File, ex.path))
	uprobeOffsets, ok := uprobeDetails.Offsets()
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.HasLen(uprobeOffsets, len(uprobeSyms)))
	infoEx, err := OpenExecutable(uprobeDetails.File)
	qt.Assert(t, qt.IsNil(err))
	var symnames = make([]string, len(uprobeOffsets))
	for i, offset := range uprobeOffsets {
		symOffset, err := infoEx.Symbol(offset.Offset)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(symOffset.Offset, 0))
		symnames[i] = symOffset.Symbol
	}
	qt.Assert(t, qt.ContentEquals(symnames, uprobeSyms))
}

func TestUprobeMultiInput(t *testing.T) {
	testutils.SkipIfNotSupported(t, features.HaveBPFLinkUprobeMulti())

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// Always doing same test for both uprobe and uretprobe

	// One of symbols or offsets must be given.
	_, err := ex.UprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = ex.UretprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// One address, two cookies.
	_, err = ex.UprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
		Cookies:   []uint64{2, 3},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = ex.UretprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
		Cookies:   []uint64{2, 3},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Two addresses, one refctr offset.
	_, err = ex.UprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses:     []uint64{1, 2},
		RefCtrOffsets: []uint64{4},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = ex.UretprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses:     []uint64{1, 2},
		RefCtrOffsets: []uint64{4},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// It's either symbols or addresses.
	_, err = ex.UprobeMulti(uprobeSyms, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = ex.UretprobeMulti(uprobeSyms, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// No addresses and no symbols
	_, err = ex.UprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = ex.UretprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// PID not found
	_, err = ex.UprobeMulti(uprobeSyms, prog, &UprobeMultiOptions{
		// pid_t is int32, overflowing it will return EINVAL.
		PID: math.MaxInt32,
	})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	_, err = ex.UretprobeMulti(uprobeSyms, prog, &UprobeMultiOptions{
		PID: math.MaxInt32,
	})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))
}

func TestUprobeMultiResolveOk(t *testing.T) {
	ex := uprobeTarget(t)
	addrSym1, err := ex.address(uprobeSyms[0], 0, 0)
	qt.Assert(t, qt.IsNil(err))
	addrSym2, err := ex.address(uprobeSyms[1], 0, 0)
	qt.Assert(t, qt.IsNil(err))
	addrSym3, err := ex.address(uprobeSyms[2], 0, 0)
	qt.Assert(t, qt.IsNil(err))

	addrs, err := ex.addresses(uprobeSyms, nil, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(addrs, []uint64{addrSym1, addrSym2, addrSym3}))

	addrs, err = ex.addresses(uprobeSyms, nil, []uint64{5, 10, 11})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(addrs, []uint64{addrSym1 + 5, addrSym2 + 10, addrSym3 + 11}))

	addrs, err = ex.addresses(uprobeSyms, []uint64{1, 2, 3}, nil)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.DeepEquals(addrs, []uint64{1, 2, 3}))
}

func TestUprobeMultiResolveFail(t *testing.T) {
	ex := uprobeTarget(t)

	// No input
	_, err := ex.addresses(nil, nil, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Different dimensions for Addresses and Offsets
	_, err = ex.addresses(nil, []uint64{100, 200}, []uint64{5, 10, 11})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Different dimensions for symbols and Offsets
	_, err = ex.addresses(uprobeSyms, nil, []uint64{5, 10})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))
}

func TestUprobeMultiCookie(t *testing.T) {
	testutils.SkipIfNotSupported(t, features.HaveBPFLinkUprobeMulti())

	ex := uprobeTarget(t)
	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// uprobe
	um, err := ex.UprobeMulti(uprobeSyms, prog,
		&UprobeMultiOptions{
			Cookies: []uint64{1, 2, 3},
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = um.Close()

	// uretprobe
	um, err = ex.UretprobeMulti(uprobeSyms, prog,
		&UprobeMultiOptions{
			Cookies: []uint64{3, 2, 1},
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = um.Close()
}

func TestUprobeMultiProgramCall(t *testing.T) {
	testutils.SkipIfNotSupported(t, features.HaveBPFLinkUprobeMulti())

	ex := uprobeTarget(t)
	test := func(retprobe bool, expected uint32) {
		m, p := newUpdaterMapProg(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti)

		var um Link
		var err error

		// Open UprobeMulti on the executable for the given symbol
		// and attach it to the ebpf program created above.
		if retprobe {
			um, err = ex.UretprobeMulti(uprobeSyms, p, nil)
		} else {
			um, err = ex.UprobeMulti(uprobeSyms, p, nil)
		}
		if err != nil {
			t.Fatal(err)
		}

		runTarget(t, ex)

		// Detach link.
		if err := um.Close(); err != nil {
			t.Fatal(err)
		}

		assertMapValueGE(t, m, 0, expected)

		// Reset map value to 0 at index 0.
		if err := m.Update(uint32(0), uint32(0), ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}

		runTarget(t, ex)

		// Assert that this time the value has not been updated.
		assertMapValue(t, m, 0, 0)
	}

	// all 3 uprobes should trigger for entry uprobes
	test(false, 3)

	// Only uprobe_returns returns to its caller, see uprobeSyms.
	test(true, 1)
}
