package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nathanjsweet/ebpf"
)

func main() {
	fileName := flag.String("file", "", "specific object file to print")
	flag.Parse()

	oF, err := os.Open(*fileName)
	if err != nil {
		panic(err)
	}
	defer oF.Close()
	progs, maps, err := ebpf.GetSpecsFromELF(oF)
	if err != nil {
		panic(err)
	}
	fmt.Println("Maps:")
	for k, v := range maps {
		fmt.Printf("\t%s:\n", k)
		fmt.Printf("\t\tMapType:    %s\n", v.MapType())
		fmt.Printf("\t\tKeySize:    %d\n", v.KeySize())
		fmt.Printf("\t\tValueSize:  %d\n", v.ValueSize())
		fmt.Printf("\t\tMaxEntries: %d\n", v.MaxEntries())
		fmt.Printf("\t\tFlags:      %d\n", v.Flags())
	}
	fmt.Println("\nPrograms:")
	for k, v := range progs {
		fmt.Printf("\t%s:\n", k)
		fmt.Printf("\t\tProgType:      %s\n", v.ProgType())
		fmt.Printf("\t\tLicense:       %s\n", v.License())
		fmt.Printf("\t\tKernelVersion: %d\n", v.KernelVersion())
		fmt.Printf("\t\tInstructions:\n")
		fmt.Printf("%s", v.Instructions().StringIndent(3))
	}
	fmt.Println("")
}
