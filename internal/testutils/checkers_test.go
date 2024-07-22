package testutils

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestIsDeepCopy(t *testing.T) {
	type s struct {
		basic  int
		array  [1]*int
		array0 [0]int
		ptr    *int
		slice  []*int
		ifc    any
		m      map[*int]*int
		rec    *s
	}

	key := 1
	copy := func() *s {
		v := &s{
			0,
			[...]*int{new(int)},
			[...]int{},
			new(int),
			[]*int{new(int)},
			new(int),
			map[*int]*int{&key: new(int)},
			nil,
		}
		v.rec = v
		return v
	}

	a, b := copy(), copy()
	qt.Check(t, qt.IsNil(IsDeepCopy(a, b).Check(nil)))

	a.basic++
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"basic": .*`))

	a = copy()
	(*a.array[0])++
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"array": index 0: .*`))

	a = copy()
	a.array[0] = nil
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"array": index 0: .*`))

	a = copy()
	a.array = b.array
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"array": index 0: .*`))

	a = copy()
	(*a.ptr)++
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"ptr": .*`))

	a = copy()
	a.ptr = b.ptr
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"ptr": .*`))

	a = copy()
	(*a.slice[0])++
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"slice": .*`))

	a = copy()
	a.slice[0] = nil
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"slice": .*`))

	a = copy()
	a.slice = nil
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"slice": .*`))

	a = copy()
	a.slice = b.slice
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"slice": .*`))

	a = copy()
	*(a.ifc.(*int))++
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"ifc": .*`))

	a = copy()
	a.ifc = b.ifc
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"ifc": .*`))

	a = copy()
	a.rec = b.rec
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"rec": .*`))

	a = copy()
	a.m = b.m
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"m": .*`))

	a = copy()
	(*a.m[&key])++
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"m": .*`))

	a = copy()
	a.m[new(int)] = new(int)
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"m": .*`))

	a = copy()
	delete(a.m, &key)
	qt.Check(t, qt.ErrorMatches(IsDeepCopy(a, b).Check(nil), `"m": .*`))
}
