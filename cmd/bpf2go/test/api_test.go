package test

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestLoadingSpec(t *testing.T) {
	spec, err := loadTest()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't load spec:", err)
	}

	if spec == nil {
		t.Fatal("Got a nil spec")
	}
}

func TestLoadingObjects(t *testing.T) {
	var objs testObjects
	err := loadTestObjects(&objs, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't load objects:", err)
	}
	defer objs.Close()

	if objs.Filter == nil {
		t.Error("Loading returns an object with nil programs")
	}

	if objs.Map1 == nil {
		t.Error("Loading returns an object with nil maps")
	}
}

func TestTypes(t *testing.T) {
	if testEHOOPY != 0 {
		t.Error("Expected testEHOOPY to be 0, got", testEHOOPY)
	}
	if testEFROOD != 1 {
		t.Error("Expected testEFROOD to be 0, got", testEFROOD)
	}

	e := testE(0)
	if size := unsafe.Sizeof(e); size != 4 {
		t.Error("Expected size of exampleE to be 4, got", size)
	}

	bf := testBarfoo{}
	if size := unsafe.Sizeof(bf); size != 16 {
		t.Error("Expected size of exampleE to be 16, got", size)
	}
	if reflect.TypeOf(bf.Bar).Kind() != reflect.Int64 {
		t.Error("Expected testBarfoo.Bar to be int64")
	}
	if reflect.TypeOf(bf.Baz).Kind() != reflect.Bool {
		t.Error("Expected testBarfoo.Baz to be bool")
	}
	if reflect.TypeOf(bf.Boo) != reflect.TypeOf(e) {
		t.Error("Expected testBarfoo.Boo to be exampleE")
	}
}
