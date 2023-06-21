// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at https://go.dev/LICENSE.

package sysenc

import (
	"reflect"
	"sync"
)

// dataLayout describes an abstract array of the form:
//
//	[count]struct{
//	    contents [size]byte
//	    padding [padding]byte
//	}
type dataLayout struct {
	count   int
	size    int
	padding int
}

var invalidLayout = dataLayout{-1, -1, -1}

func (dl *dataLayout) valid() bool {
	return *dl != invalidLayout
}

// length returns the total length including padding.
func (dl *dataLayout) length() int {
	if !dl.valid() {
		return 0
	}

	return dl.count * (dl.size + dl.padding)
}

// normalise transforms a layout so that count is either zero or one.
//
//	[count]struct{ [size]byte }
//	becomes:
//	[0/1]struct{ [size*count]byte }
//
// Produces an invalid layout if the transformation would introduce interior
// padding.
func (dl *dataLayout) normalise() {
	if !dl.valid() || dl.count <= 1 {
		return
	}

	if dl.padding != 0 {
		*dl = invalidLayout
		return
	}

	size := dl.size * dl.count
	*dl = dataLayout{1, size, 0}
}

var cachedLayouts sync.Map // map[reflect.Type]dataLayout

func layoutOf(data any) dataLayout {
	if data == nil {
		return invalidLayout
	}

	typ := reflect.TypeOf(data)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	isSlice := false
	if typ.Kind() == reflect.Slice {
		// Slices are only allowed as the root type and are therefore not
		// allowed in layoutOfRecurse.
		typ = typ.Elem()
		isSlice = true
	}

	var layout dataLayout
	if cachedLayout, ok := cachedLayouts.Load(typ); ok {
		layout = cachedLayout.(dataLayout)
	} else {
		layout = layoutOfRecurse(typ)
		if typ.Kind() == reflect.Struct {
			cachedLayouts.Store(typ, layout)
		}
	}

	v := reflect.Indirect(reflect.ValueOf(data))
	if !v.IsValid() {
		// Nil pointer.
		return invalidLayout
	}

	if isSlice {
		layout.normalise()
		if layout.valid() {
			layout.count = v.Len()
		}
	}

	return layout
}

func layoutOfRecurse(t reflect.Type) dataLayout {
	switch t.Kind() {
	case reflect.Array:
		layout := layoutOfRecurse(t.Elem())
		layout.normalise()
		if layout.valid() {
			layout.count = t.Len()
		}
		return layout

	case reflect.Struct:
		sum := 0
		offset := uintptr(0)
		for i, n := 0, t.NumField(); i < n; i++ {
			field := t.Field(i)
			if !field.IsExported() && field.Name != "_" {
				return invalidLayout
			}
			layout := layoutOfRecurse(field.Type)
			layout.normalise()
			if !layout.valid() {
				// field.Type contains padding.
				return invalidLayout
			}
			if field.Offset != offset {
				// There is padding before this field.
				return invalidLayout
			}
			sum += layout.size
			offset = field.Offset + uintptr(layout.size)
		}
		return dataLayout{1, sum, int(t.Size()) - sum}

	case reflect.Bool,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return dataLayout{1, int(t.Size()), 0}

	default:
		return invalidLayout
	}
}
