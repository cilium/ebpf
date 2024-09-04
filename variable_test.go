package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestVariableSpec(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/loader-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, spec.Variables["hidden"])

	const want uint32 = 12345

	// Update a variable in each type of data section (.bss,.data,.rodata)
	assert.NoError(t, spec.Variables["key1"].Set(want))
	assert.NoError(t, spec.Variables["key2"].Set(want))
	assert.NoError(t, spec.Variables["key3"].Set(want))

	var v uint32
	assert.NoError(t, spec.Variables["key1"].Get(&v))
	assert.EqualValues(t, want, v)
	assert.NoError(t, spec.Variables["key2"].Get(&v))
	assert.EqualValues(t, want, v)
	assert.NoError(t, spec.Variables["key3"].Get(&v))
	assert.EqualValues(t, want, v)

	// Composite values.
	type structT struct {
		A, B uint64
	}
	assert.NoError(t, spec.Variables["struct_var"].Set(structT{1, 2}))

	var s structT
	assert.NoError(t, spec.Variables["struct_var"].Get(&s))
	assert.Equal(t, structT{1, 2}, s)
}

func TestVariableSpecCopy(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/loader-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	cpy := spec.Copy()

	// Update a variable in a section with only a single variable (.rodata.test).
	const want uint32 = 0xfefefefe
	wantb := []byte{0xfe, 0xfe, 0xfe, 0xfe} // Same byte sequence regardless of endianness
	assert.NoError(t, cpy.Variables["arg2"].Set(want))
	assert.Equal(t, wantb, cpy.Maps[".rodata.test"].Contents[0].Value)

	// Verify that the original underlying MapSpec was not modified.
	zero := make([]byte, 4)
	assert.Equal(t, zero, spec.Maps[".rodata.test"].Contents[0].Value)
}
