package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal"
)

func FuzzSpec(f *testing.F) {
	f.Add(mustBTFHeader(f))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < binary.Size(btfHeader{}) {
			t.Skip("data is too short")
		}

		spec, err := loadRawSpec(bytes.NewReader(data), internal.NativeEndian, nil)
		if err != nil {
			if spec != nil {
				t.Fatal("spec is not nil")
			}
			return
		}

		if spec == nil {
			t.Fatal("spec is nil")
		}

		for typ, err := range spec.All() {
			if err == nil {
				fmt.Fprintf(io.Discard, "%+10v", typ)
			}
		}
	})
}

func FuzzExtInfo(f *testing.F) {
	f.Add(mustBTFHeader(f), []byte("\x00foo\x00barfoo\x00"))

	f.Fuzz(func(t *testing.T, data, strings []byte) {
		if len(data) < binary.Size(btfExtHeader{}) {
			t.Skip("data is too short")
		}

		table, err := readStringTable(bytes.NewReader(strings), nil)
		if err != nil {
			t.Skip("invalid string table")
		}

		emptySpec := specFromTypes(t, nil)
		emptySpec.strings = table

		info, err := loadExtInfos(bytes.NewReader(data), internal.NativeEndian, emptySpec)
		if err != nil {
			if info != nil {
				t.Fatal("info is not nil")
			}
		} else if info == nil {
			t.Fatal("info is nil")
		}
	})
}

func mustBTFHeader(f *testing.F) []byte {
	buf, err := binary.Append(nil, internal.NativeEndian, &btfHeader{
		Magic:   btfMagic,
		Version: 1,
		HdrLen:  uint32(binary.Size(btfHeader{})),
	})
	qt.Assert(f, qt.IsNil(err))
	return buf
}
