package gen

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/cmd/bpf2go/internal"
)

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

func TestEnums(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflict=%v", conflict), func(t *testing.T) {
			var buf bytes.Buffer
			args := GenerateArgs{
				Package: "foo",
				Stem:    "bar",
				Types: []btf.Type{
					&btf.Enum{Name: "EnumName", Size: 4, Values: []btf.EnumValue{
						{Name: "V1", Value: 1}, {Name: "V2", Value: 2}, {Name: "conflict", Value: 0}}},
				},
				Output: &buf,
			}
			if conflict {
				args.Types = append(args.Types, &btf.Struct{Name: "conflict", Size: 4})
			}
			err := Generate(args)
			qt.Assert(t, qt.IsNil(err))

			str := buf.String()

			qt.Assert(t, qt.Matches(str, wsSeparated("barEnumNameV1", "barEnumName", "=", "1")))
			qt.Assert(t, qt.Matches(str, wsSeparated("barEnumNameV2", "barEnumName", "=", "2")))
			qt.Assert(t, qt.Matches(str, wsSeparated("barEnumNameConflict", "barEnumName", "=", "0")))

			// short enum element names, only generated if they don't conflict with other decls
			qt.Assert(t, qt.Matches(str, wsSeparated("barV1", "barEnumName", "=", "1")))
			qt.Assert(t, qt.Matches(str, wsSeparated("barV2", "barEnumName", "=", "2")))

			pred := qt.Matches(str, wsSeparated("barConflict", "barEnumName", "=", "0"))
			if conflict {
				qt.Assert(t, qt.Not(pred))
			} else {
				qt.Assert(t, pred)
			}
		})
	}
}

func wsSeparated(terms ...string) *regexp.Regexp {
	return regexp.MustCompile(strings.Join(terms, `\s+`))
}
