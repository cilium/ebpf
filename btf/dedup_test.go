package btf

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func countTypes(typs ...Type) int {
	i := 0
	visited := make(map[Type]struct{})
	for _, typ := range typs {
		for range postorder(typ, visited) {
			i++
		}
	}
	return i
}

func TestDedupSKBuff(t *testing.T) {
	vmlinux := vmlinuxTestdataBytes(t)
	spec, err := loadRawSpec(vmlinux, nil)
	qt.Assert(t, qt.IsNil(err))

	var skBuffOne *Struct
	err = spec.TypeByName("sk_buff", &skBuffOne)
	qt.Assert(t, qt.IsNil(err))

	skbCount := countTypes(skBuffOne)

	var skBuffTwo *Struct
	spec = spec.Copy()
	qt.Assert(t, qt.IsNil(err))
	err = spec.TypeByName("sk_buff", &skBuffTwo)
	qt.Assert(t, qt.IsNil(err))

	deduper := newDeduper()

	types := []Type{skBuffOne, skBuffTwo}
	for i, typ := range types {
		types[i], err = deduper.deduplicate(typ)
	}
	qt.Assert(t, qt.IsNil(err))

	dedupedCount := countTypes(types...)
	qt.Assert(t, qt.Equals(skbCount, dedupedCount), qt.Commentf("Expected deduplicated sk_buff to have same number of types as original"))
}

func TestDedupVmlinux(t *testing.T) {
	vmlinux := vmlinuxTestdataBytes(t)

	spec1, err := loadRawSpec(vmlinux, nil)
	qt.Assert(t, qt.IsNil(err))

	spec2 := spec1.Copy()

	rootTypes := func(spec *Spec) []Type {
		refs := make(map[Type]int)
		for t := range spec.All() {
			refs[t] = 0
		}
		for t := range spec.All() {
			for child := range children(t) {
				refs[*child]++
			}
		}
		types := make([]Type, 0)
		for typ := range refs {
			if refs[typ] == 0 {
				types = append(types, typ)
			}
		}
		return types
	}

	spec1Roots := rootTypes(spec1)
	spec1TypeCount := countTypes(spec1Roots...)
	spec2Roots := rootTypes(spec2)
	types := append(spec1Roots, spec2Roots...)

	deduper := newDeduper()

	for i, typ := range types {
		types[i], err = deduper.deduplicate(typ)
		qt.Assert(t, qt.IsNil(err))
	}
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(countTypes(types...), spec1TypeCount), qt.Commentf("Expected deduplicated vmlinux to have same number of types as original"))
}

func BenchmarkDeduplicateSKBuff(b *testing.B) {
	vmlinux := vmlinuxTestdataBytes(b)
	base, err := loadRawSpec(vmlinux, nil)
	qt.Assert(b, qt.IsNil(err))

	var types []Type
	for i := 0; i <= b.N; i++ {
		var skBuff *Struct
		err = base.Copy().TypeByName("sk_buff", &skBuff)
		qt.Assert(b, qt.IsNil(err))
		types = append(types, skBuff)
	}

	dedup := newDeduper()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = dedup.deduplicate(types[i])
		qt.Assert(b, qt.IsNil(err))
	}
}

func BenchmarkDeduplicateVMLinux(b *testing.B) {
	vmlinux := vmlinuxTestdataBytes(b)
	base, err := loadRawSpec(vmlinux, nil)
	qt.Assert(b, qt.IsNil(err))

	var types [][]Type
	for i := 0; i <= b.N; i++ {
		var specTypes []Type
		for typ := range base.Copy().All() {
			specTypes = append(specTypes, typ)
		}
		types = append(types, specTypes)
	}

	dedup := newDeduper()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, typ := range types[i] {
			_, err = dedup.deduplicate(typ)
			qt.Assert(b, qt.IsNil(err))
		}
	}
}
