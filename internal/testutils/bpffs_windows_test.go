package testutils_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestTempBPFFS(t *testing.T) {
	var progPath, mapPath string
	t.Run("pin", func(t *testing.T) {
		tmp := testutils.TempBPFFS(t)
		progPath = filepath.Join(tmp, "prog")
		mapPath = filepath.Join(tmp, "map")

		var buffer bytes.Buffer
		insns := asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		}
		err := insns.Marshal(&buffer, internal.NativeEndian)
		qt.Assert(t, qt.IsNil(err))

		progFd, err := sys.ProgLoad(&sys.ProgLoadAttr{
			ProgType: 999, // SAMPLE
			License:  sys.NewStringPointer(""),
			InsnCnt:  uint32(buffer.Len() / asm.InstructionSize),
			Insns:    sys.SlicePointer(buffer.Bytes()),
		})
		qt.Assert(t, qt.IsNil(err))
		defer progFd.Close()

		err = sys.ObjPin(&sys.ObjPinAttr{
			BpfFd:    progFd.Uint(),
			Pathname: sys.NewStringPointer(progPath),
		})
		qt.Assert(t, qt.IsNil(err))

		mapFd, err := sys.MapCreate(&sys.MapCreateAttr{
			MapType:    2, // ARRAY
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 1,
		})
		qt.Assert(t, qt.IsNil(err))
		defer mapFd.Close()

		err = sys.ObjPin(&sys.ObjPinAttr{
			BpfFd:    progFd.Uint(),
			Pathname: sys.NewStringPointer(mapPath),
		})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNil(mapFd.Close()))
	})

	_, err := sys.ObjGet(&sys.ObjGetAttr{
		Pathname: sys.NewStringPointer(progPath),
	})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	_, err = sys.ObjGet(&sys.ObjGetAttr{
		Pathname: sys.NewStringPointer(mapPath),
	})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))
}
