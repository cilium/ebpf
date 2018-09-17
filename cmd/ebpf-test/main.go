// Program ebpf-test allows testing eBPF from an ELF file.
//
// The input to the program is read from stdin and the output is written
// to stdout. The binary uses the exit code of the BPF.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/newtools/ebpf"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: <elf-file> <prog-name>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(42)
	}

	path := flag.Arg(0)
	coll, err := ebpf.LoadCollection(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't load %s: %v\n", path, err)
		os.Exit(42)
	}

	progName := flag.Arg(1)
	prog, ok := coll.Programs[progName]
	if !ok {
		fmt.Fprintf(os.Stderr, "%v does not contain program %v\n", path, progName)
		os.Exit(42)
	}

	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't read stdin: %v\n", err)
		os.Exit(42)
	}

	ret, out, err := prog.Test(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't run %v: %v\n", progName, err)
		os.Exit(42)
	}

	if out != nil {
		if _, err := os.Stdout.Write(out); err != nil {
			fmt.Fprintf(os.Stderr, "Can't write output: %v\n", err)
			os.Exit(42)
		}
	}

	os.Exit(int(ret))
}
