package kconfig

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"

	qt "github.com/frankban/quicktest"
)

func BenchmarkParse(b *testing.B) {
	f, err := os.Open("testdata/config-6.2.15-300.fc38.x86_64.gz")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := Parse(f)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseGziped(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/config-6.2.15-300.fc38.x86_64.gz")
	if err != nil {
		t.Fatal("Error reading /testdata/config-6.2.15-300.fc38.x86_64.gz: ", err)
	}
	defer f.Close()

	_, err = Parse(f)
	if err != nil {
		t.Fatal("Error parsing gziped kconfig: ", err)
	}
}

func TestProcessKconfigBadLine(t *testing.T) {
	t.Parallel()

	m := make(map[string]string)

	err := processKconfigLine("CONFIG_FOO", m)
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("line has no '='"))

	err = processKconfigLine("CONFIG_FOO=", m)
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("line has no value"))
}

func TestPutValue(t *testing.T) {
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
					Encoding: btf.Unsigned,
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
					Encoding: btf.Signed,
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
			comment: "Type is not btf.Array of btf.Int of size 1 which is not btf.Bool",
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
			err := PutValue(make([]byte, 0), c.typ, c.value)

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
		err = PutValue(data, c.typ, c.value)

		qt.Assert(t, err, qt.IsNil)

		qt.Assert(t, data, qt.DeepEquals, expected)
	}
}
