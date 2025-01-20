package ebpf

import (
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestLoadNativeImage(t *testing.T) {
	for _, file := range []string{
		"testdata/empty.sys",
		"testdata/printk.sys",
	} {
		t.Run(filepath.Base(file), func(t *testing.T) {
			coll, err := LoadCollection(file)
			qt.Assert(t, qt.IsNil(err))
			defer coll.Close()

			for _, m := range coll.Maps {
				info, err := m.Info()
				qt.Assert(t, qt.IsNil(err))
				t.Log("map", info.Name)
			}

			for _, p := range coll.Programs {
				info, err := p.Info()
				qt.Assert(t, qt.IsNil(err))
				t.Log("program", info.Name)
			}
		})
	}
}
