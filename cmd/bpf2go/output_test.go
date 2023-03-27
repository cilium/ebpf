package main

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
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
			qt.Assert(t, err, qt.IsNil)
			qt.Assert(t, len(result), qt.Equals, len(test.out))
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
			qt.Assert(t, err, qt.IsNotNil)
			qt.Assert(t, result, qt.IsNil)
		})
	}
}

var typesEqual = qt.CmpEquals(cmp.Comparer(func(a, b btf.Type) bool {
	return a == b
}))

func TestCollectFromSpec(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(fmt.Sprintf("testdata/minimal-%s.elf", internal.ClangEndian))
	if err != nil {
		t.Fatal(err)
	}

	map1 := spec.Maps["map1"]

	maps, programs, types, err := collectFromSpec(spec, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, maps, qt.ContentEquals, []string{"map1"})
	qt.Assert(t, programs, qt.ContentEquals, []string{"filter"})
	qt.Assert(t, types, typesEqual, []btf.Type{map1.Key, map1.Value})

	_, _, types, err = collectFromSpec(spec, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, types, typesEqual, ([]btf.Type)(nil))

	_, _, types, err = collectFromSpec(spec, []string{"barfoo"}, true)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, types, typesEqual, []btf.Type{map1.Value})
}
