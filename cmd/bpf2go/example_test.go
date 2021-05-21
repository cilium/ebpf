package main

import (
	"fmt"
)

// This will use the current bpf2go code to generate the example test.
// To utilize it, run `go generate .` in the current folder
//go:generate go run ./... -cc clang-9 example testdata/minimal.c

func Example() {
	var objs exampleObjects
	if err := loadExampleObjects(&objs, nil); err != nil {
		panic("Can't load objects: " + err.Error())
	}
	defer objs.Close()

	// Do something useful with the program.
	fmt.Println(objs.Filter.String())
}
