package pin

import (
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/testutils/testmain"
)

func mustPinnedProgram(t *testing.T, path string) *ebpf.Program {
	t.Helper()

	typ := ebpf.SocketFilter
	if platform.IsWindows {
		typ = ebpf.WindowsXDPTest
	}

	spec := &ebpf.ProgramSpec{
		Name: "test",
		Type: typ,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 2, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	p, err := ebpf.NewProgram(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	if err := p.Pin(path); err != nil {
		t.Fatal(err)
	}

	return p
}

func mustPinnedMap(t *testing.T, path string) *ebpf.Map {
	t.Helper()

	typ := ebpf.Array
	if platform.IsWindows {
		typ = ebpf.WindowsArray
	}

	spec := &ebpf.MapSpec{
		Name:       "test",
		Type:       typ,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })

	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}

	return m
}

func TestLoad(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.10", "reading program fdinfo")

	tmp := testutils.TempBPFFS(t)

	mpath := filepath.Join(tmp, "map")
	ppath := filepath.Join(tmp, "prog")

	mustPinnedMap(t, mpath)
	mustPinnedProgram(t, ppath)

	_, err := Load(tmp, nil)
	qt.Assert(t, qt.IsNotNil(err))

	m, err := Load(mpath, nil)
	qt.Assert(t, qt.IsNil(err))
	defer m.Close()
	qt.Assert(t, qt.Satisfies(m, testutils.Contains[*ebpf.Map]))

	p, err := Load(ppath, nil)
	qt.Assert(t, qt.IsNil(err))
	defer p.Close()
	qt.Assert(t, qt.Satisfies(p, testutils.Contains[*ebpf.Program]))
}

func TestMain(m *testing.M) {
	testmain.Run(m)
}
