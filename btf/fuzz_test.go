package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func FuzzSpec(f *testing.F) {
	var buf bytes.Buffer
	err := binary.Write(&buf, internal.NativeEndian, &btfHeader{
		Magic:   btfMagic,
		Version: 1,
		HdrLen:  uint32(binary.Size(btfHeader{})),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
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

		for _, typ := range spec.types {
			fmt.Fprintf(io.Discard, "%+10v", typ)
		}
	})
}

func FuzzExtInfo(f *testing.F) {
	var buf bytes.Buffer
	err := binary.Write(&buf, internal.NativeEndian, &btfExtHeader{
		Magic:   btfMagic,
		Version: 1,
		HdrLen:  uint32(binary.Size(btfExtHeader{})),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes(), []byte("\x00foo\x00barfoo\x00"))

	emptySpec := newSpec()

	f.Fuzz(func(t *testing.T, data, strings []byte) {
		if len(data) < binary.Size(btfExtHeader{}) {
			t.Skip("data is too short")
		}

		table, err := readStringTable(bytes.NewReader(strings), nil)
		if err != nil {
			t.Skip("invalid string table")
		}

		info, err := loadExtInfos(bytes.NewReader(data), internal.NativeEndian, emptySpec, table)
		if err != nil {
			if info != nil {
				t.Fatal("info is not nil")
			}
		} else if info == nil {
			t.Fatal("info is nil")
		}
	})
}
