package kconfig

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"

	qt "github.com/frankban/quicktest"
)

func TestParseKconfig(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
		"CONFIG_TRISTATE": "m",
		"CONFIG_BOOL":     "y",
		"CONFIG_CHAR":     "100",
		"CONFIG_USHORT":   "30000",
		"CONFIG_INT":      "123456",
		"CONFIG_ULONG":    "0xDEADBEEFC0DE",
		"CONFIG_STR":      `"abracad"`,
		"CONFIG_FOO":      `"foo"`,
	}

	config, err := ParseKconfig("test.kconfig", false)
	if err != nil {
		t.Fatal("Error parsing kconfig: ", err)
	}

	qt.Assert(t, config, qt.DeepEquals, expected)
}

func TestParseKconfigGziped(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
		"CONFIG_TRISTATE": "m",
		"CONFIG_BOOL":     "y",
		"CONFIG_CHAR":     "100",
		"CONFIG_USHORT":   "30000",
		"CONFIG_INT":      "123456",
		"CONFIG_ULONG":    "0xDEADBEEFC0DE",
		"CONFIG_STR":      `"abracad"`,
		"CONFIG_FOO":      `"foo"`,
	}

	content, err := os.ReadFile("test.kconfig")
	if err != nil {
		t.Fatal(err)
	}

	fout, err := os.Create("/tmp/test.kconfig.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fout.Name())

	zw := gzip.NewWriter(fout)
	defer zw.Close()

	_, err = zw.Write(content)
	if err != nil {
		t.Fatal(err)
	}

	err = zw.Flush()
	if err != nil {
		t.Fatal(err)
	}

	config, err := ParseKconfig("/tmp/test.kconfig.gz", true)
	if err != nil {
		t.Fatal("Error parsing gziped kconfig: ", err)
	}

	qt.Assert(t, config, qt.DeepEquals, expected)
}

func TestPatchKconfig(t *testing.T) {
	t.Parallel()

	config := map[string]string{
		"CONFIG_TRISTATE": "m",
		"CONFIG_BOOL":     "y",
		"CONFIG_CHAR":     "100",
		"CONFIG_USHORT":   "30000",
		"CONFIG_INT":      "123456",
		"CONFIG_ULONG":    "0xDEADBEEFC0DE",
		"CONFIG_STR":      `"abracad"`,
		"CONFIG_FOO":      `"bar"`,
	}

	patch := `
CONFIG_FOO="foo"
CONFIG_BAR="42"
`

	expected := map[string]string{
		"CONFIG_TRISTATE": "m",
		"CONFIG_BOOL":     "y",
		"CONFIG_CHAR":     "100",
		"CONFIG_USHORT":   "30000",
		"CONFIG_INT":      "123456",
		"CONFIG_ULONG":    "0xDEADBEEFC0DE",
		"CONFIG_STR":      `"abracad"`,
		"CONFIG_FOO":      `"foo"`,
		"CONFIG_BAR":      `"42"`,
	}

	err := PatchKconfig(config, patch)
	if err != nil {
		t.Fatal("Error parsing kconfig: ", err)
	}

	qt.Assert(t, config, qt.DeepEquals, expected)
}

func TestProcessKconfigBadLine(t *testing.T) {
	t.Parallel()

	m := make(map[string]string)

	err := processKconfigLine("CONFIG_FOO", m, false)
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("line has no '='"))

	err = processKconfigLine("CONFIG_FOO=", m, false)
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("line has no value"))
}

func TestPutKconfigValue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		typ      btf.Type
		value    string
		expected any
		comment  string
	}

	cases := []testCase{
		{
			typ: &btf.Int{
				Size:     1,
				Encoding: btf.Bool,
			},
			value:    "n",
			expected: int8(0),
		},
		{
			typ: &btf.Int{
				Size:     1,
				Encoding: btf.Bool,
			},
			value:    "y",
			expected: int8(1),
		},
		{
			typ: &btf.Int{
				Size:     1,
				Encoding: btf.Bool,
			},
			value:   "foo",
			comment: "Bad value",
		},
		{
			typ:     &btf.Int{},
			comment: "Encoding is not Bool",
		},
		{
			typ: &btf.Int{
				Encoding: btf.Bool,
			},
			comment: "Size is not 1",
		},
		{
			typ: &btf.Enum{
				Name: "libbpf_tristate",
			},
			value:    "y",
			expected: int64(TriYes),
		},
		{
			typ: &btf.Enum{
				Name: "libbpf_tristate",
			},
			value:    "n",
			expected: int64(TriNo),
		},
		{
			typ: &btf.Enum{
				Name: "libbpf_tristate",
			},
			value:    "m",
			expected: int64(TriModule),
		},
		{
			typ: &btf.Enum{
				Name: "libbpf_tristate",
			},
			value:   "foo",
			comment: "Bad value",
		},
		{
			typ: &btf.Enum{
				Name: "error",
			},
			comment: "Enum name is wrong",
		},
		{
			typ:     &btf.Array{},
			value:   "y",
			comment: "Type is not btf.Int",
		},
		{
			typ: &btf.Int{
				Size: 1,
			},
			value:    "255",
			expected: uint8(255),
		},
		{
			typ: &btf.Int{
				Size: 2,
			},
			value:    "0xcafe",
			expected: uint16(0xcafe),
		},
		{
			typ: &btf.Int{
				Size: 2,
			},
			value:    "0755",
			expected: uint16(0755),
		},
		{
			typ: &btf.Int{
				Size:     4,
				Encoding: btf.Signed,
			},
			value:    "-2147483648",
			expected: int32(-2147483648),
		},
		{
			typ: &btf.Int{
				Size:     4,
				Encoding: btf.Signed,
			},
			value:    "+2147483647",
			expected: int32(+2147483647),
		},
		{
			typ: &btf.Int{
				Size: 4,
			},
			value:    "0xcafec0de",
			expected: uint32(0xcafec0de),
		},
		{
			typ: &btf.Int{
				Size:     8,
				Encoding: btf.Signed,
			},
			value:    "+1000000000000",
			expected: int64(1000000000000),
		},
		{
			typ: &btf.Int{
				Size: 8,
			},
			value:    "1000000000000",
			expected: uint64(1000000000000),
		},
		{
			typ: &btf.Int{
				Size: 1,
			},
			value:   "foo",
			comment: "Value is not an int",
		},
		{
			typ:     &btf.Array{},
			value:   "1",
			comment: "Type is not btf.Int",
		},
		{
			typ: &btf.Int{
				Size: 16,
			},
			value:   "1",
			comment: "Size is wrong",
		},
		{
			typ: &btf.Typedef{
				Type: &btf.Int{
					Size: 1,
				},
			},
			value:    "1",
			expected: uint8(1),
		},
		{
			typ: &btf.Array{
				Type: &btf.Int{
					Size:     1,
					Encoding: btf.Char,
				},
				Nelems: 6,
			},
			value:    `"foobar"`,
			expected: []byte("foobar"),
		},
		{
			typ: &btf.Array{
				Type: &btf.Int{
					Size:     1,
					Encoding: btf.Char,
				},
				Nelems: 3,
			},
			value:    `"foobar"`,
			expected: []byte("foo"),
		},
		{
			typ: &btf.Array{
				Type: &btf.Int{
					Size:     1,
					Encoding: btf.Char,
				},
				Nelems: 2,
			},
			value:    `"42"`,
			expected: []byte("42"),
		},
		{
			typ:     &btf.Int{},
			value:   `"foo"`,
			comment: "Type is not btf.Array",
		},
		{
			typ:     &btf.Array{},
			value:   `"foo"`,
			comment: "Type is not btf.Array of btf.Int",
		},
		{
			typ: &btf.Array{
				Type: &btf.Int{
					Size:     1,
					Encoding: btf.Bool,
				},
			},
			value:   `"foo"`,
			comment: "Type is not btf.Array of btf.Char",
		},
		{
			typ: &btf.Array{
				Type: &btf.Int{
					Size:     4,
					Encoding: btf.Char,
				},
			},
			value:   `"foo"`,
			comment: "Type is not btf.Array of btf.Char of size 1",
		},
		{
			typ: &btf.Array{
				Type: &btf.Int{
					Size:     1,
					Encoding: btf.Char,
				},
			},
			value:   `"foo`,
			comment: `Value does not start and end with '"'`,
		},
	}

	for _, c := range cases {
		if len(c.comment) > 0 {
			err := PutKconfigValue(make([]byte, 0), c.typ, c.value)

			qt.Assert(t, err, qt.IsNotNil, qt.Commentf(c.comment))

			continue
		}

		var buf bytes.Buffer
		err := binary.Write(&buf, internal.NativeEndian, c.expected)
		if err != nil {
			t.Fatal(err)
		}

		expected := buf.Bytes()
		data := make([]byte, len(expected))
		err = PutKconfigValue(data, c.typ, c.value)

		qt.Assert(t, err, qt.IsNil)

		qt.Assert(t, data, qt.DeepEquals, expected)
	}
}
