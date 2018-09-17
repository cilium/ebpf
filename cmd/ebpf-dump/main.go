// Program ebpf-dump writes the contents of an ELF file to stdout.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/newtools/ebpf"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: <elf-file>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	spec, err := ebpf.LoadCollectionSpec(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	fmt.Println("Maps:")
	for k, v := range spec.Maps {
		fmt.Printf("\t%s:\n", k)
		fmt.Printf("\t\tMapType:    %s\n", v.Type)
		fmt.Printf("\t\tKeySize:    %d\n", v.KeySize)
		fmt.Printf("\t\tValueSize:  %d\n", v.ValueSize)
		fmt.Printf("\t\tMaxEntries: %d\n", v.MaxEntries)
		fmt.Printf("\t\tFlags:      %d\n", v.Flags)
	}
	fmt.Println("\nPrograms:")
	for k, v := range spec.Programs {
		fmt.Printf("\t%s:\n", k)
		fmt.Printf("\t\tProgType:      %s\n", v.Type)
		fmt.Printf("\t\tLicense:       %s\n", v.License)
		fmt.Printf("\t\tKernelVersion: %d\n", v.KernelVersion)
		fmt.Printf("\t\tInstructions:\n")
		fmt.Printf("%.3s", v.Instructions)
	}
	fmt.Println("")
}
