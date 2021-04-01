package btf

import (
	"errors"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
)

func TestCoreAreTypesCompatible(t *testing.T) {
	tests := []struct {
		a, b       Type
		compatible bool
	}{
		{&Void{}, &Void{}, true},
		{&Struct{Name: "a"}, &Struct{Name: "b"}, true},
		{&Union{Name: "a"}, &Union{Name: "b"}, true},
		{&Union{Name: "a"}, &Struct{Name: "b"}, false},
		{&Enum{Name: "a"}, &Enum{Name: "b"}, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "b"}, true},
		{&Int{Name: "a", Size: 2}, &Int{Name: "b", Size: 4}, true},
		{&Int{Offset: 1}, &Int{}, false},
		{&Pointer{Target: &Void{}}, &Pointer{Target: &Void{}}, true},
		{&Pointer{Target: &Void{}}, &Void{}, false},
		{&Array{Type: &Void{}}, &Array{Type: &Void{}}, true},
		{&Array{Type: &Int{}}, &Array{Type: &Void{}}, false},
		{&FuncProto{Return: &Int{}}, &FuncProto{Return: &Void{}}, false},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Name: "a", Type: &Void{}}}},
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Name: "b", Type: &Void{}}}},
			true,
		},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Void{}}}},
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Int{}}}},
			false,
		},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Void{}}, {Type: &Void{}}}},
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Void{}}}},
			false,
		},
	}

	for _, test := range tests {
		err := coreAreTypesCompatible(test.a, test.b)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected types to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		}

		err = coreAreTypesCompatible(test.b, test.a)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected reversed types to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected reversed types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		}
	}

	for _, invalid := range []Type{&Var{}, &Datasec{}} {
		err := coreAreTypesCompatible(invalid, invalid)
		if errors.Is(err, errImpossibleRelocation) {
			t.Errorf("Expected an error for %T, not errImpossibleRelocation", invalid)
		} else if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCoreAreMembersCompatible(t *testing.T) {
	tests := []struct {
		a, b       Type
		compatible bool
	}{
		{&Struct{Name: "a"}, &Struct{Name: "b"}, true},
		{&Union{Name: "a"}, &Union{Name: "b"}, true},
		{&Union{Name: "a"}, &Struct{Name: "b"}, true},
		{&Enum{Name: "a"}, &Enum{Name: "b"}, false},
		{&Enum{Name: "a"}, &Enum{Name: "a___foo"}, true},
		{&Enum{Name: "a"}, &Enum{Name: ""}, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "b"}, false},
		{&Fwd{Name: "a"}, &Fwd{Name: "a___foo"}, true},
		{&Fwd{Name: "a"}, &Fwd{Name: ""}, true},
		{&Int{Name: "a", Size: 2}, &Int{Name: "b", Size: 4}, true},
		{&Int{Offset: 1}, &Int{}, false},
		{&Pointer{Target: &Void{}}, &Pointer{Target: &Void{}}, true},
		{&Pointer{Target: &Void{}}, &Void{}, false},
		{&Array{Type: &Int{Size: 1}}, &Array{Type: &Int{Encoding: Signed}}, true},
	}

	for _, test := range tests {
		err := coreAreMembersCompatible(test.a, test.b)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected members to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected members to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		}

		err = coreAreMembersCompatible(test.b, test.a)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected reversed members to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected reversed members to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		}
	}

	for _, invalid := range []Type{&Void{}, &FuncProto{}, &Var{}, &Datasec{}} {
		err := coreAreMembersCompatible(invalid, invalid)
		if errors.Is(err, errImpossibleRelocation) {
			t.Errorf("Expected an error for %T, not errImpossibleRelocation", invalid)
		} else if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCoreAccessor(t *testing.T) {
	for _, valid := range []string{
		"0",
		"1:0",
		"1:0:3:34:10:1",
	} {
		_, err := parseCoreAccessor(valid)
		if err != nil {
			t.Errorf("Parse %q: %s", valid, err)
		}
	}

	for _, invalid := range []string{
		"",
		"-1",
		":",
		"0:",
		":12",
		"4294967296",
	} {
		_, err := parseCoreAccessor(invalid)
		if err == nil {
			t.Errorf("Accepted invalid accessor %q", invalid)
		}
	}
}

func TestCoreFindEnumValue(t *testing.T) {
	a := &Enum{Values: []EnumValue{{"foo", 23}, {"bar", 42}}}
	b := &Enum{Values: []EnumValue{
		{"foo___flavour", 0},
		{"bar", 123},
		{"garbage", 3},
	}}

	invalid := []struct {
		name   string
		local  Type
		target Type
		acc    coreAccessor
		err    error
	}{
		{"o-o-b accessor", a, b, coreAccessor{len(a.Values)}, nil},
		{"long accessor", a, b, coreAccessor{0, 1}, nil},
		{"wrong target", a, &Void{}, coreAccessor{0, 1}, nil},
		{
			"no matching value",
			b, a,
			coreAccessor{2},
			errImpossibleRelocation,
		},
	}

	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := coreFindEnumValue(test.local, test.acc, test.target)
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("Expected %s, got %s", test.err, err)
			}
			if err == nil {
				t.Fatal("Accepted invalid case")
			}
		})
	}

	valid := []struct {
		name                    string
		local, target           Type
		acc                     coreAccessor
		localValue, targetValue int32
	}{
		{"a to b", a, b, coreAccessor{0}, 23, 0},
		{"b to a", b, a, coreAccessor{1}, 123, 42},
	}

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			local, target, err := coreFindEnumValue(test.local, test.acc, test.target)
			qt.Assert(t, err, qt.IsNil)
			qt.Check(t, local.Value, qt.Equals, test.localValue)
			qt.Check(t, target.Value, qt.Equals, test.targetValue)
		})
	}
}

func TestCoreRelocation(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/*.elf"), func(t *testing.T, file string) {
		rd, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()

		spec, err := LoadSpecFromReader(rd)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}

		errs := map[string]error{
			"err_ambiguous":         errAmbiguousRelocation,
			"err_ambiguous_flavour": errAmbiguousRelocation,
		}

		for section := range spec.funcInfos {
			name := strings.TrimPrefix(section, "socket_filter/")
			t.Run(name, func(t *testing.T) {
				prog, err := spec.Program(section, 1)
				if err != nil {
					t.Fatal("Retrieve program:", err)
				}

				relos, err := ProgramFixups(prog, spec)
				if want := errs[name]; want != nil {
					if !errors.Is(err, want) {
						t.Fatal("Expected", want, "got", err)
					}
					return
				}

				if err != nil {
					t.Fatal("Can't relocate against itself:", err)
				}

				for offset, relo := range relos {
					if relo.Local != relo.Target {
						// Since we're relocating against ourselves both values
						// should match.
						t.Errorf("offset %d: local %v doesn't match target %d", offset, relo.Local, relo.Target)
					}
				}
			})
		}
	})
}

func TestCoreCopyWithoutQualifiers(t *testing.T) {
	qualifiers := []struct {
		name string
		fn   func(Type) Type
	}{
		{"const", func(t Type) Type { return &Const{Type: t} }},
		{"volatile", func(t Type) Type { return &Volatile{Type: t} }},
		{"restrict", func(t Type) Type { return &Restrict{Type: t} }},
		{"typedef", func(t Type) Type { return &Typedef{Type: t} }},
	}

	for _, test := range qualifiers {
		t.Run(test.name+" cycle", func(t *testing.T) {
			root := &Volatile{}
			root.Type = test.fn(root)

			_, err := copyType(root, skipQualifierAndTypedef)
			qt.Assert(t, err, qt.Not(qt.IsNil))
		})
	}

	for _, a := range qualifiers {
		for _, b := range qualifiers {
			t.Run(a.name+" "+b.name, func(t *testing.T) {
				v := a.fn(&Pointer{Target: b.fn(&Int{Name: "z"})})
				want := &Pointer{Target: &Int{Name: "z"}}

				got, err := copyType(v, skipQualifierAndTypedef)
				qt.Assert(t, err, qt.IsNil)
				qt.Assert(t, got, qt.DeepEquals, want)
			})
		}
	}

	t.Run("long chain", func(t *testing.T) {
		root := &Int{Name: "abc"}
		v := Type(root)
		for i := 0; i < maxTypeDepth; i++ {
			q := qualifiers[rand.Intn(len(qualifiers))]
			v = q.fn(v)
			t.Log(q.name)
		}

		got, err := copyType(v, skipQualifierAndTypedef)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, got, qt.DeepEquals, root)
	})
}
