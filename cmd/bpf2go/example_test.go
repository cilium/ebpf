package main

import (
	"fmt"
)

// $BPF_CLANG, $BPF_STRIP and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $BPF_STRIP example testdata/minimal.c

func Example() {
	var objs exampleObjects
	if err := loadExampleObjects(&objs, nil); err != nil {
		panic("Can't load objects: " + err.Error())
	}
	defer objs.Close()

	// Do something useful with the program.
	fmt.Println(objs.Filter.String())
}
