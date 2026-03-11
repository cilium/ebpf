package internal

import (
	"fmt"
	"reflect"
)

// IsNil returns an error if i is a nil pointer or a nil interface. Otherwise,
// it returns nil.
func IsNil(i any) error {
	v := reflect.ValueOf(i)
	switch v.Kind() {
	case reflect.Invalid:
		return fmt.Errorf("nil interface")
	case reflect.Pointer:
		if v.IsNil() {
			return fmt.Errorf("nil %T", i)
		}
	}
	return nil
}
