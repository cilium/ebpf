package main

import (
	"testing"
)

func TestLoadingSpec(t *testing.T) {
	specs, err := newExampleSpecs()
	if err != nil {
		t.Fatal("Can't load specs:", err)
	}

	cpy := specs.Copy()
	if cpy == specs || cpy.ProgramFilter == specs.ProgramFilter {
		t.Error("Copy doesn't copy all fields")
	}

	spec := specs.CollectionSpec()
	if spec.Programs["filter"] != specs.ProgramFilter {
		t.Error("CollectionSpec copies programs instead of using the same reference")
	}

	objs, err := specs.Load(nil)
	if err != nil {
		t.Fatal("Can't load objects:", err)
	}
	defer objs.Close()

	if objs.ProgramFilter == nil {
		t.Error("Loading returns an object with nil references")
	}
}
