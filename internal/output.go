package internal

import (
	"reflect"
	"strings"
)

// GoTypeName is like %T, but elides the package name.
//
// Pointers to a type are peeled off.
func GoTypeName(t any) string {
	rT := reflect.TypeOf(t)
	for rT.Kind() == reflect.Pointer {
		rT = rT.Elem()
	}

	name := rT.Name()
	if pkgPath := rT.PkgPath(); pkgPath != "" {
		name = strings.ReplaceAll(name, pkgPath+".", "")
	}

	return name
}
