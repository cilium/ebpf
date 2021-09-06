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
		{&Int{OffsetBits: 1}, &Int{}, false},
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
		{&Int{OffsetBits: 1}, &Int{}, false},
		{&Pointer{Target: &Void{}}, &Pointer{Target: &Void{}}, true},
		{&Pointer{Target: &Void{}}, &Void{}, false},
		{&Array{Type: &Int{Size: 1}}, &Array{Type: &Int{Encoding: Signed}}, true},
		{&Float{Size: 2}, &Float{Size: 4}, true},
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

func TestCoreFindField(t *testing.T) {
	ptr := &Pointer{}
	u16 := &Int{Size: 2}
	u32 := &Int{Size: 4}
	aFields := []Member{
		{Name: "foo", Type: ptr, OffsetBits: 1},
		{Name: "bar", Type: u16, OffsetBits: 2},
	}
	bFields := []Member{
		{Name: "foo", Type: ptr, OffsetBits: 10},
		{Name: "bar", Type: u32, OffsetBits: 20},
		{Name: "other", OffsetBits: 4},
	}
	aStruct := &Struct{Members: aFields, Size: 2}
	bStruct := &Struct{Members: bFields, Size: 7}
	aArray := &Array{Nelems: 4, Type: u16}
	bArray := &Array{Nelems: 3, Type: u32}

	invalid := []struct {
		name          string
		local, target Type
		acc           coreAccessor
		err           error
	}{
		{
			"unsupported type",
			&Void{}, &Void{},
			coreAccessor{0, 0},
			ErrNotSupported,
		},
		{
			"different types",
			&Union{}, &Array{Type: u16},
			coreAccessor{0},
			errImpossibleRelocation,
		},
		{
			"invalid composite accessor",
			aStruct, aStruct,
			coreAccessor{0, len(aStruct.Members)},
			nil,
		},
		{
			"invalid array accessor",
			aArray, aArray,
			coreAccessor{0, int(aArray.Nelems)},
			nil,
		},
		{
			"o-o-b array accessor",
			aArray, bArray,
			coreAccessor{0, int(bArray.Nelems)},
			errImpossibleRelocation,
		},
		{
			"no match",
			bStruct, aStruct,
			coreAccessor{0, 2},
			errImpossibleRelocation,
		},
		{
			"incompatible match",
			&Union{Members: []Member{{Name: "foo", Type: &Pointer{}}}},
			&Union{Members: []Member{{Name: "foo", Type: &Int{}}}},
			coreAccessor{0, 0},
			errImpossibleRelocation,
		},
	}

	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := coreFindField(test.local, test.acc, test.target)
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("Expected %s, got %s", test.err, err)
			}
			if err == nil {
				t.Fatal("Accepted invalid case")
			}
			t.Log(err)
		})
	}

	bits := func(typ Type) uint32 {
		sz, err := Sizeof(typ)
		if err != nil {
			t.Fatal(err)
		}
		return uint32(sz * 8)
	}

	anon := func(t Type, offset uint32) []Member {
		return []Member{{Type: t, OffsetBits: offset}}
	}

	anonStruct := func(m ...Member) Member {
		return Member{Type: &Struct{Members: m}}
	}

	anonUnion := func(m ...Member) Member {
		return Member{Type: &Union{Members: m}}
	}

	valid := []struct {
		name                    string
		local                   Type
		target                  Type
		acc                     coreAccessor
		localField, targetField coreField
	}{
		{
			"array[0]",
			aArray,
			bArray,
			coreAccessor{0, 0},
			coreField{u16, 0},
			coreField{u32, 0},
		},
		{
			"array[1]",
			aArray,
			bArray,
			coreAccessor{0, 1},
			coreField{u16, bits(aArray.Type)},
			coreField{u32, bits(bArray.Type)},
		},
		{
			"array[0] with base offset",
			aArray,
			bArray,
			coreAccessor{1, 0},
			coreField{u16, bits(aArray)},
			coreField{u32, bits(bArray)},
		},
		{
			"array[2] with base offset",
			aArray,
			bArray,
			coreAccessor{1, 2},
			coreField{u16, bits(aArray) + 2*bits(aArray.Type)},
			coreField{u32, bits(bArray) + 2*bits(bArray.Type)},
		},
		{
			"flex array",
			&Struct{Members: []Member{{Name: "foo", Type: &Array{Nelems: 0, Type: u16}}}},
			&Struct{Members: []Member{{Name: "foo", Type: &Array{Nelems: 0, Type: u32}}}},
			coreAccessor{0, 0, 9000},
			coreField{u16, bits(u16) * 9000},
			coreField{u32, bits(u32) * 9000},
		},
		{
			"struct.0",
			aStruct, bStruct,
			coreAccessor{0, 0},
			coreField{ptr, 1},
			coreField{ptr, 10},
		},
		{
			"struct.0 anon",
			aStruct, &Struct{Members: anon(bStruct, 23)},
			coreAccessor{0, 0},
			coreField{ptr, 1},
			coreField{ptr, 23 + 10},
		},
		{
			"struct.0 with base offset",
			aStruct, bStruct,
			coreAccessor{3, 0},
			coreField{ptr, 3*bits(aStruct) + 1},
			coreField{ptr, 3*bits(bStruct) + 10},
		},
		{
			"struct.1",
			aStruct, bStruct,
			coreAccessor{0, 1},
			coreField{u16, 2},
			coreField{u32, 20},
		},
		{
			"struct.1 anon",
			aStruct, &Struct{Members: anon(bStruct, 1)},
			coreAccessor{0, 1},
			coreField{u16, 2},
			coreField{u32, 1 + 20},
		},
		{
			"union.1",
			&Union{Members: aFields, Size: 32},
			&Union{Members: bFields, Size: 32},
			coreAccessor{0, 1},
			coreField{u16, 2},
			coreField{u32, 20},
		},
		{
			"interchangeable composites",
			&Struct{
				Members: []Member{
					anonStruct(anonUnion(Member{Name: "_1", Type: u16})),
				},
			},
			&Struct{
				Members: []Member{
					anonUnion(anonStruct(Member{Name: "_1", Type: u16})),
				},
			},
			coreAccessor{0, 0, 0, 0},
			coreField{u16, 0},
			coreField{u16, 0},
		},
	}

	checkCoreField := func(t *testing.T, got, want coreField) {
		t.Helper()
		qt.Check(t, got.Type, qt.Equals, want.Type, qt.Commentf("type should match"))
		qt.Check(t, got.offset, qt.Equals, want.offset, qt.Commentf("offset should match"))
	}

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			localField, targetField, err := coreFindField(test.local, test.acc, test.target)
			qt.Assert(t, err, qt.IsNil)
			checkCoreField(t, localField, test.localField)
			checkCoreField(t, targetField, test.targetField)
		})
	}
}

func TestCoreFindFieldCyclical(t *testing.T) {
	members := []Member{{Name: "foo", Type: &Pointer{}}}

	cyclicStruct := &Struct{}
	cyclicStruct.Members = []Member{{Type: cyclicStruct}}

	cyclicUnion := &Union{}
	cyclicUnion.Members = []Member{{Type: cyclicUnion}}

	cyclicArray := &Array{Nelems: 1}
	cyclicArray.Type = &Pointer{Target: cyclicArray}

	tests := []struct {
		name          string
		local, cyclic Type
	}{
		{"struct", &Struct{Members: members}, cyclicStruct},
		{"union", &Union{Members: members}, cyclicUnion},
		{"array", &Array{Nelems: 2, Type: &Int{}}, cyclicArray},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := coreFindField(test.local, coreAccessor{0, 0}, test.cyclic)
			if !errors.Is(err, errImpossibleRelocation) {
				t.Fatal("Should return errImpossibleRelocation, got", err)
			}
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

				relos, err := prog.Fixups(spec)
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
