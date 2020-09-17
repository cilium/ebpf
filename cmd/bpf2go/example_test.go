package main

import (
	"fmt"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-9 example testdata/minimal.c

func Example() {
	specs, err := newExampleSpecs()
	if err != nil {
		fmt.Println("Can't load specs:", err)
		os.Exit(1)
	}

	objs, err := specs.Load(nil)
	if err != nil {
		fmt.Println("Can't load objects:", err)
		os.Exit(1)
	}
	defer objs.Close()

	// Do something useful with the program.
	fmt.Println(objs.ProgramFilter.String())
}
