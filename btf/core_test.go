package btf

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestCheckTypeCompatibility(t *testing.T) {
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
		{&Pointer{Target: &Void{}}, &Pointer{Target: &Void{}}, true},
		{&Pointer{Target: &Void{}}, &Void{}, false},
		{&Array{Index: &Void{}, Type: &Void{}}, &Array{Index: &Void{}, Type: &Void{}}, true},
		{&Array{Index: &Void{}, Type: &Int{}}, &Array{Index: &Void{}, Type: &Void{}}, false},
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
		{&FuncProto{Return: &Typedef{Type: &Int{}}}, &FuncProto{Return: &Int{}}, true},
		{&FuncProto{Return: &Typedef{Type: &Int{}}}, &FuncProto{Return: &Void{}}, false},
	}

	for _, test := range tests {
		err := CheckTypeCompatibility(test.a, test.b)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected types to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		} else {
			if !errors.Is(err, errIncompatibleTypes) {
				t.Errorf("Expected types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		}

		err = CheckTypeCompatibility(test.b, test.a)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected reversed types to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		} else {
			if !errors.Is(err, errIncompatibleTypes) {
				t.Errorf("Expected reversed types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		}
	}

	for _, invalid := range []Type{&Var{}, &Datasec{}} {
		err := CheckTypeCompatibility(invalid, invalid)
		if errors.Is(err, errIncompatibleTypes) {
			t.Errorf("Expected an error for %T, not errIncompatibleTypes", invalid)
		} else if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCOREAreMembersCompatible(t *testing.T) {
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

func TestCOREAccessor(t *testing.T) {
	for _, valid := range []string{
		"0",
		"1:0",
		"1:0:3:34:10:1",
	} {
		_, err := parseCOREAccessor(valid)
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
		_, err := parseCOREAccessor(invalid)
		if err == nil {
			t.Errorf("Accepted invalid accessor %q", invalid)
		}
	}
}

func TestCOREFindEnumValue(t *testing.T) {
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
		localValue, targetValue uint64
	}{
		{"a to b", a, b, coreAccessor{0}, 23, 0},
		{"b to a", b, a, coreAccessor{1}, 123, 42},
	}

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			local, target, err := coreFindEnumValue(test.local, test.acc, test.target)
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(local.Value, test.localValue))
			qt.Check(t, qt.Equals(target.Value, test.targetValue))
		})
	}
}

func TestCOREFindField(t *testing.T) {
	ptr := &Pointer{}
	u16 := &Int{Size: 2}
	u32 := &Int{Size: 4}
	aFields := []Member{
		{Name: "foo", Type: ptr, Offset: 8},
		{Name: "bar", Type: u16, Offset: 16},
		{Name: "baz", Type: u32, Offset: 32, BitfieldSize: 3},
		{Name: "quux", Type: u32, Offset: 35, BitfieldSize: 10},
		{Name: "quuz", Type: u32, Offset: 45, BitfieldSize: 8},
	}
	bFields := []Member{
		{Name: "foo", Type: ptr, Offset: 16},
		{Name: "bar", Type: u32, Offset: 8},
		{Name: "other", Offset: 4},
		// baz is separated out from the other bitfields
		{Name: "baz", Type: u32, Offset: 64, BitfieldSize: 3},
		// quux's type changes u32->u16
		{Name: "quux", Type: u16, Offset: 96, BitfieldSize: 10},
		// quuz becomes a normal field
		{Name: "quuz", Type: u16, Offset: 112},
	}

	aStruct := &Struct{Members: aFields, Size: 48}
	bStruct := &Struct{Members: bFields, Size: 80}
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
		{
			"unsized type",
			bStruct, &Func{},
			// non-zero accessor to force calculating the offset.
			coreAccessor{1},
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

	bytes := func(typ Type) uint32 {
		sz, err := Sizeof(typ)
		if err != nil {
			t.Fatal(err)
		}
		return uint32(sz)
	}

	anon := func(t Type, offset Bits) []Member {
		return []Member{{Type: t, Offset: offset}}
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
			coreField{u16, 0, 0, 0},
			coreField{u32, 0, 0, 0},
		},
		{
			"array[1]",
			aArray,
			bArray,
			coreAccessor{0, 1},
			coreField{u16, bytes(aArray.Type), 0, 0},
			coreField{u32, bytes(bArray.Type), 0, 0},
		},
		{
			"array[0] with base offset",
			aArray,
			bArray,
			coreAccessor{1, 0},
			coreField{u16, bytes(aArray), 0, 0},
			coreField{u32, bytes(bArray), 0, 0},
		},
		{
			"array[2] with base offset",
			aArray,
			bArray,
			coreAccessor{1, 2},
			coreField{u16, bytes(aArray) + 2*bytes(aArray.Type), 0, 0},
			coreField{u32, bytes(bArray) + 2*bytes(bArray.Type), 0, 0},
		},
		{
			"flex array",
			&Struct{Members: []Member{{Name: "foo", Type: &Array{Nelems: 0, Type: u16}}}},
			&Struct{Members: []Member{{Name: "foo", Type: &Array{Nelems: 0, Type: u32}}}},
			coreAccessor{0, 0, 9000},
			coreField{u16, bytes(u16) * 9000, 0, 0},
			coreField{u32, bytes(u32) * 9000, 0, 0},
		},
		{
			"struct.0",
			aStruct, bStruct,
			coreAccessor{0, 0},
			coreField{ptr, 1, 0, 0},
			coreField{ptr, 2, 0, 0},
		},
		{
			"struct.0 anon",
			aStruct, &Struct{Members: anon(bStruct, 24)},
			coreAccessor{0, 0},
			coreField{ptr, 1, 0, 0},
			coreField{ptr, 3 + 2, 0, 0},
		},
		{
			"struct.0 with base offset",
			aStruct, bStruct,
			coreAccessor{3, 0},
			coreField{ptr, 3*bytes(aStruct) + 1, 0, 0},
			coreField{ptr, 3*bytes(bStruct) + 2, 0, 0},
		},
		{
			"struct.1",
			aStruct, bStruct,
			coreAccessor{0, 1},
			coreField{u16, 2, 0, 0},
			coreField{u32, 1, 0, 0},
		},
		{
			"struct.1 anon",
			aStruct, &Struct{Members: anon(bStruct, 24)},
			coreAccessor{0, 1},
			coreField{u16, 2, 0, 0},
			coreField{u32, 3 + 1, 0, 0},
		},
		{
			"union.1",
			&Union{Members: aFields, Size: 32},
			&Union{Members: bFields, Size: 32},
			coreAccessor{0, 1},
			coreField{u16, 2, 0, 0},
			coreField{u32, 1, 0, 0},
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
			coreField{u16, 0, 0, 0},
			coreField{u16, 0, 0, 0},
		},
		{
			"struct.2 (bitfield baz)",
			aStruct, bStruct,
			coreAccessor{0, 2},
			coreField{u32, 4, 0, 3},
			coreField{u32, 8, 0, 3},
		},
		{
			"struct.3 (bitfield quux)",
			aStruct, bStruct,
			coreAccessor{0, 3},
			coreField{u32, 4, 3, 10},
			coreField{u16, 12, 0, 10},
		},
		{
			"struct.4 (bitfield quuz)",
			aStruct, bStruct,
			coreAccessor{0, 4},
			coreField{u32, 4, 13, 8},
			coreField{u16, 14, 0, 0},
		},
	}

	allowCoreField := cmp.AllowUnexported(coreField{})

	checkCOREField := func(t *testing.T, which string, got, want coreField) {
		t.Helper()
		if diff := cmp.Diff(want, got, allowCoreField); diff != "" {
			t.Errorf("%s mismatch (-want +got):\n%s", which, diff)
		}
	}

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			localField, targetField, err := coreFindField(test.local, test.acc, test.target)
			qt.Assert(t, qt.IsNil(err))
			checkCOREField(t, "local", localField, test.localField)
			checkCOREField(t, "target", targetField, test.targetField)
		})
	}
}

func TestCOREFindFieldCyclical(t *testing.T) {
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

func TestCORERelocation(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/*.elf"), func(t *testing.T, file string) {
		rd, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()

		spec, extInfos, err := LoadSpecAndExtInfosFromReader(rd)
		if err != nil {
			t.Fatal(err)
		}

		if extInfos == nil {
			t.Skip("No ext_infos")
		}

		errs := map[string]error{
			"err_ambiguous":         errAmbiguousRelocation,
			"err_ambiguous_flavour": errAmbiguousRelocation,
		}

		for section := range extInfos.funcInfos {
			name := strings.TrimPrefix(section, "socket/")
			t.Run(name, func(t *testing.T) {
				var relos []*CORERelocation
				for _, reloInfo := range extInfos.relocationInfos[section].infos {
					relos = append(relos, reloInfo.relo)
				}

				fixups, err := CORERelocate(relos, []*Spec{spec}, spec.imm.byteOrder, spec.TypeID)
				if want := errs[name]; want != nil {
					if !errors.Is(err, want) {
						t.Fatal("Expected", want, "got", err)
					}
					return
				}

				if err != nil {
					t.Fatal("Can't relocate against itself:", err)
				}

				for offset, fixup := range fixups {
					if want := fixup.local; !fixup.skipLocalValidation && want != fixup.target {
						// Since we're relocating against ourselves both values
						// should match.
						t.Errorf("offset %d: local %v doesn't match target %d (kind %s)", offset, fixup.local, fixup.target, fixup.kind)
					}
				}
			})
		}
	})
}

func TestCOREReloFieldSigned(t *testing.T) {
	for _, typ := range []Type{&Int{}, &Enum{}} {
		t.Run(fmt.Sprintf("%T with invalid target", typ), func(t *testing.T) {
			relo := &CORERelocation{
				typ, coreAccessor{0}, reloFieldSigned, 0,
			}
			fixup, err := coreCalculateFixup(relo, &Void{}, internal.NativeEndian, dummyTypeID)
			qt.Assert(t, qt.IsTrue(fixup.poison))
			qt.Assert(t, qt.IsNil(err))
		})
	}

	t.Run("type without signedness", func(t *testing.T) {
		relo := &CORERelocation{
			&Array{}, coreAccessor{0}, reloFieldSigned, 0,
		}
		_, err := coreCalculateFixup(relo, &Array{}, internal.NativeEndian, dummyTypeID)
		qt.Assert(t, qt.ErrorIs(err, errNoSignedness))
	})
}

func TestCOREReloFieldShiftU64(t *testing.T) {
	typ := &Struct{
		Members: []Member{
			{Name: "A", Type: &Fwd{}},
		},
	}

	for _, relo := range []*CORERelocation{
		{typ, coreAccessor{0, 0}, reloFieldRShiftU64, 1},
		{typ, coreAccessor{0, 0}, reloFieldLShiftU64, 1},
	} {
		t.Run(relo.kind.String(), func(t *testing.T) {
			_, err := coreCalculateFixup(relo, typ, internal.NativeEndian, dummyTypeID)
			qt.Assert(t, qt.ErrorIs(err, errUnsizedType))
		})
	}
}

func TestCORERelosKmodTypeID(t *testing.T) {
	a := &Int{Name: "a"}
	b := &Int{Name: "b"}

	relos := []*CORERelocation{
		{&Int{}, coreAccessor{0}, reloTypeIDTarget, 0},
	}

	typeID := func(t Type) (TypeID, error) {
		if t == a {
			return 42, nil
		}
		return 0, ErrNotFound
	}

	fixups, err := coreCalculateFixups(
		relos,
		[]Type{a, b},
		internal.NativeEndian,
		typeID,
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(fixups[0].poison))
	qt.Assert(t, qt.Equals(fixups[0].target, 42))

	fixups, err = coreCalculateFixups(
		relos,
		[]Type{b},
		internal.NativeEndian,
		typeID,
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(fixups[0].poison))
}

func BenchmarkCORESkBuff(b *testing.B) {
	spec := vmlinuxTestdataSpec(b)

	var skb *Struct
	err := spec.TypeByName("sk_buff", &skb)
	qt.Assert(b, qt.IsNil(err))

	skbID, err := spec.TypeID(skb)
	qt.Assert(b, qt.IsNil(err))

	lenIndex := slices.IndexFunc(skb.Members, func(m Member) bool {
		return m.Name == "len"
	})
	qt.Assert(b, qt.Not(qt.Equals(lenIndex, -1)))

	var pktHashTypes *Enum
	err = spec.TypeByName("pkt_hash_types", &pktHashTypes)
	qt.Assert(b, qt.IsNil(err))

	pktHashTypesID, err := spec.TypeID(pktHashTypes)
	qt.Assert(b, qt.IsNil(err))

	for _, relo := range []*CORERelocation{
		{skb, coreAccessor{0, lenIndex}, reloFieldByteOffset, skbID},
		{skb, coreAccessor{0, lenIndex}, reloFieldByteSize, skbID},
		{skb, coreAccessor{0, lenIndex}, reloFieldExists, skbID},
		{skb, coreAccessor{0, lenIndex}, reloFieldSigned, skbID},
		{skb, coreAccessor{0, lenIndex}, reloFieldLShiftU64, skbID},
		{skb, coreAccessor{0, lenIndex}, reloFieldRShiftU64, skbID},
		{skb, coreAccessor{0}, reloTypeIDLocal, skbID},
		{skb, coreAccessor{0}, reloTypeIDTarget, skbID},
		{skb, coreAccessor{0}, reloTypeExists, skbID},
		{skb, coreAccessor{0}, reloTypeSize, skbID},
		{pktHashTypes, coreAccessor{0}, reloEnumvalExists, pktHashTypesID},
		{pktHashTypes, coreAccessor{0}, reloEnumvalValue, pktHashTypesID},
	} {
		b.Run(relo.kind.String(), func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err = CORERelocate([]*CORERelocation{relo}, []*Spec{spec}, spec.imm.byteOrder, spec.TypeID)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestCORETypesMatch(t *testing.T) {
	tests := []struct {
		a, b       Type
		match      bool
		reversible bool
	}{
		{&Void{}, &Void{}, true, true},
		{&Int{Size: 32}, &Int{Size: 32}, true, true},
		{&Int{Size: 64}, &Int{Size: 32}, false, true},
		{&Int{Size: 32}, &Int{Size: 32, Encoding: Signed}, false, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "a"}, true, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "b___new"}, false, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "a___new"}, true, true},
		{&Fwd{Name: "a"}, &Struct{Name: "a___new"}, false, true},
		{&Fwd{Name: "a"}, &Union{Name: "a___new"}, false, true},
		{&Fwd{Name: "a", Kind: FwdStruct}, &Fwd{Name: "a___new", Kind: FwdUnion}, false, true},
		{&Pointer{&Fwd{Name: "a", Kind: FwdStruct}}, &Pointer{&Struct{Name: "a___new"}}, true, true},
		{&Pointer{&Fwd{Name: "a", Kind: FwdUnion}}, &Pointer{&Union{Name: "a___new"}}, true, true},
		{&Pointer{&Fwd{Name: "a", Kind: FwdStruct}}, &Pointer{&Union{Name: "a___new"}}, false, true},
		{&Struct{Name: "a___new"}, &Union{Name: "a___new"}, false, true},
		{&Pointer{&Struct{Name: "a"}}, &Pointer{&Union{Name: "a___new"}}, false, true},
		{
			&Struct{Name: "a", Members: []Member{
				{Name: "foo", Type: &Int{}},
			}},
			&Struct{Name: "a___new", Members: []Member{
				{Name: "foo", Type: &Int{}},
			}},
			true,
			true,
		},
		{
			&Struct{Name: "a", Members: []Member{
				{Name: "foo", Type: &Int{}},
			}},
			&Struct{Name: "a___new", Members: []Member{
				{Name: "foo", Type: &Int{}},
				{Name: "bar", Type: &Int{}},
			}},
			true,
			false,
		},
		{
			&Struct{Name: "a", Members: []Member{
				{Name: "foo", Type: &Int{}},
				{Name: "bar", Type: &Int{}},
			}},
			&Struct{Name: "a___new", Members: []Member{
				{Name: "foo", Type: &Int{}},
			}},
			false,
			false,
		},
		{
			&Struct{Name: "a", Members: []Member{
				{Name: "bar", Type: &Int{}},
			}},
			&Struct{Name: "a___new", Members: []Member{
				{Name: "foo", Type: &Int{}},
			}},
			false,
			false,
		},
		{
			&Struct{Name: "a", Members: []Member{
				{Name: "foo", Type: &Int{Encoding: Signed}},
			}},
			&Struct{Name: "a___new", Members: []Member{
				{Name: "foo", Type: &Int{}},
			}},
			false,
			false,
		},
		{
			&Enum{Name: "a", Values: []EnumValue{
				{"foo", 1},
			}},
			&Enum{Name: "a___new", Values: []EnumValue{
				{"foo", 1},
			}},
			true,
			true,
		},
		{
			&Enum{Name: "a", Values: []EnumValue{
				{"foo", 1},
			}},
			&Enum{Name: "a___new", Values: []EnumValue{
				{"foo", 1},
				{"bar", 2},
			}},
			true,
			false,
		},
		{
			&Enum{Name: "a", Values: []EnumValue{
				{"foo", 1},
				{"bar", 2},
			}},
			&Enum{Name: "a___new", Values: []EnumValue{
				{"foo", 1},
			}},
			false,
			false,
		},
		{
			&Enum{Name: "a", Values: []EnumValue{
				{"foo", 1},
			}},
			&Enum{Name: "a___new", Values: []EnumValue{
				{"bar", 1},
			}},
			false,
			false,
		},
		{
			&Enum{Name: "a", Values: []EnumValue{
				{"foo", 1},
			}, Size: 1},
			&Enum{Name: "a___new", Values: []EnumValue{
				{"foo", 1},
			}, Size: 2},
			false,
			false,
		},
		{
			&Array{Type: &Int{}, Nelems: 2},
			&Array{Type: &Int{}, Nelems: 2},
			true,
			true,
		},
		{
			&Array{Type: &Int{}, Nelems: 3},
			&Array{Type: &Int{}, Nelems: 2},
			false,
			true,
		},
		{
			&Array{Type: &Void{}, Nelems: 2},
			&Array{Type: &Int{}, Nelems: 2},
			false,
			true,
		},
		{
			&FuncProto{Return: &Int{}, Params: []FuncParam{
				{Name: "foo", Type: &Int{}},
			}},
			&FuncProto{Return: &Int{}, Params: []FuncParam{
				{Name: "bar", Type: &Int{}},
			}},
			true,
			true,
		},
		{
			&FuncProto{Return: &Int{}, Params: []FuncParam{
				{Name: "foo", Type: &Int{}},
			}},
			&FuncProto{Return: &Int{}, Params: []FuncParam{
				{Name: "bar", Type: &Int{}},
				{Name: "baz", Type: &Int{}},
			}},
			false,
			true,
		},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{
				{Name: "foo", Type: &Int{}},
			}},
			&FuncProto{Return: &Int{}, Params: []FuncParam{
				{Name: "bar", Type: &Int{}},
			}},
			false,
			true,
		},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{
				{Name: "bar", Type: &Int{Encoding: Signed}},
			}},
			&FuncProto{Return: &Int{}, Params: []FuncParam{
				{Name: "bar", Type: &Int{}},
			}},
			false,
			true,
		},
	}

	for _, test := range tests {
		err := coreTypesMatch(test.a, test.b, nil)
		if test.match {
			if err != nil {
				t.Errorf("Expected types to match: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		} else {
			if !errors.Is(err, errIncompatibleTypes) {
				t.Errorf("Expected types to be incompatible: \na = %#v\nb = %#v", test.a, test.b)
				continue
			}
		}

		if test.reversible {
			err = coreTypesMatch(test.b, test.a, nil)
			if test.match {
				if err != nil {
					t.Errorf("Expected reversed types to match: %s\na = %#v\nb = %#v", err, test.a, test.b)
				}
			} else {
				if !errors.Is(err, errIncompatibleTypes) {
					t.Errorf("Expected reversed types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				}
			}
		}
	}

	for _, invalid := range []Type{&Var{}, &Datasec{}} {
		err := coreTypesMatch(invalid, invalid, nil)
		if errors.Is(err, errIncompatibleTypes) {
			t.Errorf("Expected an error for %T, not errIncompatibleTypes", invalid)
		} else if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

// dummyTypeID returns 0, nil for any passed type.
func dummyTypeID(Type) (TypeID, error) {
	return 0, nil
}
