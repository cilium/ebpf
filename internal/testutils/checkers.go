package testutils

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/go-quicktest/qt"
)

// Contains checks if interface value I is of type T. Use with qt.Satisfies:
//
//	qt.Assert(t, qt.Satisfies(p, testutils.Contains[*ebpf.Program]))
func Contains[T, I any](i I) bool {
	_, ok := any(i).(T)
	return ok
}

// IsDeepCopy checks that got is a deep copy of want.
//
// All primitive values must be equal, but pointers must be distinct.
// This is different from [reflect.DeepEqual] which will accept equal pointer values.
// That is, reflect.DeepEqual(a, a) is true, while IsDeepCopy(a, a) is false.
func IsDeepCopy[T any](got, want T) qt.Checker {
	return &deepCopyChecker[T]{got, want, make(map[pair]struct{})}
}

type pair struct {
	got, want reflect.Value
}

type deepCopyChecker[T any] struct {
	got, want T
	visited   map[pair]struct{}
}

func (dcc *deepCopyChecker[T]) Check(_ func(key string, value any)) error {
	return dcc.check(reflect.ValueOf(dcc.got), reflect.ValueOf(dcc.want))
}

func (dcc *deepCopyChecker[T]) check(got, want reflect.Value) error {
	switch want.Kind() {
	case reflect.Interface:
		return dcc.check(got.Elem(), want.Elem())

	case reflect.Pointer:
		if got.IsNil() && want.IsNil() {
			return nil
		}

		if got.IsNil() {
			return fmt.Errorf("expected non-nil pointer")
		}

		if want.IsNil() {
			return fmt.Errorf("expected nil pointer")
		}

		if got.UnsafePointer() == want.UnsafePointer() {
			return fmt.Errorf("equal pointer values")
		}

		switch want.Type() {
		case reflect.TypeOf((*bytes.Reader)(nil)):
			// bytes.Reader doesn't allow modifying it's contents, so we
			// allow a shallow copy.
			return nil
		}

		if _, ok := dcc.visited[pair{got, want}]; ok {
			// Deal with recursive types.
			return nil
		}

		dcc.visited[pair{got, want}] = struct{}{}
		return dcc.check(got.Elem(), want.Elem())

	case reflect.Slice:
		if got.IsNil() && want.IsNil() {
			return nil
		}

		if got.IsNil() {
			return fmt.Errorf("expected non-nil slice")
		}

		if want.IsNil() {
			return fmt.Errorf("expected nil slice")
		}

		if got.Len() != want.Len() {
			return fmt.Errorf("expected %d elements, got %d", want.Len(), got.Len())
		}

		if want.Len() == 0 {
			return nil
		}

		if got.UnsafePointer() == want.UnsafePointer() {
			return fmt.Errorf("equal backing memory")
		}

		fallthrough

	case reflect.Array:
		for i := 0; i < want.Len(); i++ {
			if err := dcc.check(got.Index(i), want.Index(i)); err != nil {
				return fmt.Errorf("index %d: %w", i, err)
			}
		}

		return nil

	case reflect.Struct:
		for i := 0; i < want.NumField(); i++ {
			if err := dcc.check(got.Field(i), want.Field(i)); err != nil {
				return fmt.Errorf("%q: %w", want.Type().Field(i).Name, err)
			}
		}

		return nil

	case reflect.Map:
		if got.Len() != want.Len() {
			return fmt.Errorf("expected %d items, got %d", want.Len(), got.Len())
		}

		if got.UnsafePointer() == want.UnsafePointer() {
			return fmt.Errorf("maps are equal")
		}

		iter := want.MapRange()
		for iter.Next() {
			key := iter.Key()
			got := got.MapIndex(iter.Key())
			if !got.IsValid() {
				return fmt.Errorf("key %v is missing", key)
			}

			want := iter.Value()
			if err := dcc.check(got, want); err != nil {
				return fmt.Errorf("key %v: %w", key, err)
			}
		}

		return nil

	case reflect.Chan, reflect.UnsafePointer:
		return fmt.Errorf("%s is not supported", want.Type())

	default:
		// Compare by value as usual.
		if !got.Equal(want) {
			return fmt.Errorf("%#v is not equal to %#v", got, want)
		}

		return nil
	}
}

func (dcc *deepCopyChecker[T]) Args() []qt.Arg {
	return []qt.Arg{
		{Name: "got", Value: dcc.got},
		{Name: "want", Value: dcc.want},
	}
}
