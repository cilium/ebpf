// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at https://go.dev/LICENSE.

package sysenc

import (
	"reflect"
	"sync"
)

var cachedSizes sync.Map // map[reflect.Type]int

func sizeOf(data any) int {
	if data == nil {
		return -1
	}

	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return -1
		}

		v = v.Elem()
	}

	isSlice := false
	typ := v.Type()
	if v.Kind() == reflect.Slice {
		// Slices are only allowed as the root type and are therefore not
		// allowed in layoutOfRecurse.
		typ = v.Type().Elem()
		isSlice = true
	}

	var size int
	if cachedSize, ok := cachedSizes.Load(typ); ok {
		size = cachedSize.(int)
	} else {
		size = sizeOfRecurse(typ)
		if typ.Kind() == reflect.Struct {
			cachedSizes.Store(typ, size)
		}
	}

	if isSlice && size != -1 {
		size *= v.Len()
	}

	return size
}

func sizeOfRecurse(t reflect.Type) int {
	switch t.Kind() {
	case reflect.Array:
		size := sizeOfRecurse(t.Elem())
		if size != -1 {
			size *= t.Len()
		}
		return size

	case reflect.Struct:
		offset := 0
		for i, n := 0, t.NumField(); i < n; i++ {
			field := t.Field(i)
			if !field.IsExported() && field.Name != "_" {
				return -1
			}
			if field.Offset != uintptr(offset) {
				// There is padding before this field.
				return -1
			}

			size := sizeOfRecurse(field.Type)
			if size == -1 {
				return -1
			}

			offset += size
		}

		if t.Size() != uintptr(offset) {
			// There is trailing padding in the struct.
			return -1
		}

		return -1

	case reflect.Bool,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return int(t.Size())

	default:
		return -1
	}
}
