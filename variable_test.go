package ebpf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestVariableSpec(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(spec.Variables["hidden"]))
	qt.Assert(t, qt.IsNil(spec.Variables["unreferenced"]))
	qt.Assert(t, qt.IsNotNil(spec.Variables["weak"]))

	const want uint32 = 12345

	// Update a variable in each type of data section (.bss,.data,.rodata)
	qt.Assert(t, qt.IsNil(spec.Variables["var_bss"].Set(want)))
	qt.Assert(t, qt.IsNil(spec.Variables["var_data"].Set(want)))
	qt.Assert(t, qt.IsNil(spec.Variables["var_rodata"].Set(want)))

	var v uint32
	qt.Assert(t, qt.IsNil(spec.Variables["var_bss"].Get(&v)))
	qt.Assert(t, qt.Equals(v, want))
	qt.Assert(t, qt.IsNil(spec.Variables["var_data"].Get(&v)))
	qt.Assert(t, qt.Equals(v, want))
	qt.Assert(t, qt.IsNil(spec.Variables["var_rodata"].Get(&v)))
	qt.Assert(t, qt.Equals(v, want))

	// Composite values.
	type structT struct {
		A, B uint64
	}
	qt.Assert(t, qt.IsNil(spec.Variables["var_struct"].Set(&structT{1, 2})))

	var s structT
	qt.Assert(t, qt.IsNil(spec.Variables["var_struct"].Get(&s)))
	qt.Assert(t, qt.Equals(s, structT{1, 2}))
}

func TestVariableSpecCopy(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	cpy := spec.Copy()

	// Update a variable in a section with only a single variable (.rodata).
	const want uint32 = 0xfefefefe
	wantb := []byte{0xfe, 0xfe, 0xfe, 0xfe} // Same byte sequence regardless of endianness
	qt.Assert(t, qt.IsNil(cpy.Variables["var_rodata"].Set(want)))
	qt.Assert(t, qt.DeepEquals(cpy.Maps[".rodata"].Contents[0].Value.([]byte), wantb))

	// Verify that the original underlying MapSpec was not modified.
	zero := make([]byte, 4)
	qt.Assert(t, qt.DeepEquals(spec.Maps[".rodata"].Contents[0].Value.([]byte), zero))
}
