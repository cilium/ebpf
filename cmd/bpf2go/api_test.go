package main

import (
	"testing"
)

func TestLoadingSpec(t *testing.T) {
	spec, err := loadExampleSpecs()
	if err != nil {
		t.Fatal("Can't load spec:", err)
	}

	if spec == nil {
		t.Fatal("Got a nil spec")
	}
}

func TestLoadingObjects(t *testing.T) {
	var objs struct {
		Specs exampleSpecs
		exampleObjects
	}
	if err := loadExampleObjects(&objs, nil); err != nil {
		t.Fatal("Can't load objects:", err)
	}
	defer objs.Close()

	if objs.Specs.Filter == nil {
		t.Error("Specs.Filter is nil")
	}

	if objs.Specs.Map1 == nil {
		t.Error("Specs.Map1 is nil")
	}

	if objs.Filter == nil {
		t.Error("Loading returns an object with nil programs")
	}

	if objs.Map1 == nil {
		t.Error("Loading returns an object with nil maps")
	}
}
