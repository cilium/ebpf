package gen

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/cmd/bpf2go/internal"
)

func TestOrderTypes(t *testing.T) {
	a := &btf.Int{}
	b := &btf.Int{}
	c := &btf.Int{}

	for _, test := range []struct {
		name string
		in   map[btf.Type]string
		out  []btf.Type
	}{
		{
			"order",
			map[btf.Type]string{
				a: "foo",
				b: "bar",
				c: "baz",
			},
			[]btf.Type{b, c, a},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := sortTypes(test.in)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(len(result), len(test.out)))
			for i, o := range test.out {
				if result[i] != o {
					t.Fatalf("Index %d: expected %p got %p", i, o, result[i])
				}
			}
		})
	}

	for _, test := range []struct {
		name string
		in   map[btf.Type]string
	}{
		{
			"duplicate names",
			map[btf.Type]string{
				a: "foo",
				b: "foo",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := sortTypes(test.in)
			qt.Assert(t, qt.IsNotNil(err))
			qt.Assert(t, qt.IsNil(result))
		})
	}
}

func TestPackageImport(t *testing.T) {
	var buf bytes.Buffer
	err := Generate(GenerateArgs{
		Package:    "foo",
		Stem:       "bar",
		ObjectFile: "frob.o",
		Output:     &buf,
	})
	qt.Assert(t, qt.IsNil(err))
	// NB: It'd be great to test that this is the case for callers outside of
	// this module, but that is kind of tricky.
	qt.Assert(t, qt.StringContains(buf.String(), fmt.Sprintf(`"%s"`, internal.CurrentModule)))
}

func TestCustomIdentifier(t *testing.T) {
	var buf bytes.Buffer
	args := GenerateArgs{
		Package:    "foo",
		Stem:       "bar",
		ObjectFile: "frob.o",
		Output:     &buf,
		Programs:   []string{"do_thing"},
		Identifier: strings.ToUpper,
	}
	err := Generate(args)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.StringContains(buf.String(), "DO_THING"))
}

func TestObjects(t *testing.T) {
	var buf bytes.Buffer
	args := GenerateArgs{
		Package:   "foo",
		Stem:      "bar",
		Maps:      []string{"map1"},
		Variables: []string{"var_1"},
		Programs:  []string{"prog_foo_1"},
		Output:    &buf,
	}
	err := Generate(args)
	qt.Assert(t, qt.IsNil(err))

	str := buf.String()

	qt.Assert(t, qt.StringContains(str, "Map1 *ebpf.MapSpec `ebpf:\"map1\"`"))
	qt.Assert(t, qt.StringContains(str, "Var1 *ebpf.VariableSpec `ebpf:\"var_1\"`"))
	qt.Assert(t, qt.StringContains(str, "ProgFoo1 *ebpf.ProgramSpec `ebpf:\"prog_foo_1\"`"))

	qt.Assert(t, qt.StringContains(str, "Map1 *ebpf.Map `ebpf:\"map1\"`"))
	qt.Assert(t, qt.StringContains(str, "Var1 *ebpf.Variable `ebpf:\"var_1\"`"))
	qt.Assert(t, qt.StringContains(str, "ProgFoo1 *ebpf.Program `ebpf:\"prog_foo_1\"`"))
}
