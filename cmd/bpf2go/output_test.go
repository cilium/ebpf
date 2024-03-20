package main

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
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

var typesEqualComparer = cmp.Comparer(func(a, b btf.Type) bool {
	return a == b
})

func TestCollectFromSpec(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(testutils.NativeFile(t, "testdata/minimal-%s.elf"))
	if err != nil {
		t.Fatal(err)
	}

	map1 := spec.Maps["map1"]

	maps, programs, types, err := collectFromSpec(spec, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.ContentEquals(maps, []string{"map1"}))
	qt.Assert(t, qt.ContentEquals(programs, []string{"filter"}))
	qt.Assert(t, qt.CmpEquals(types, []btf.Type{map1.Key, map1.Value}, typesEqualComparer))

	_, _, types, err = collectFromSpec(spec, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.CmpEquals[[]btf.Type](types, nil, typesEqualComparer))

	_, _, types, err = collectFromSpec(spec, []string{"barfoo"}, true)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.CmpEquals(types, []btf.Type{map1.Value}, typesEqualComparer))
}
