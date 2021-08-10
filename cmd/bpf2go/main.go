package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const helpText = `Usage: %[1]s [options] <ident> <source file> [-- <C flags>]

ident is used as the stem of all generated Go types and functions, and
must be a valid Go identifier.

source is a single C file that is compiled using the specified compiler
(usually some version of clang).

You can pass options to the compiler by appending them after a '--' argument
or by supplying -cflags. Flags passed as arguments take precedence
over flags passed via -cflags. Additionally, the program expands quotation
marks in -cflags. This means that -cflags 'foo "bar baz"' is passed to the
compiler as two arguments "foo" and "bar baz".

The program expects GOPACKAGE to be set in the environment, and should be invoked
via go generate. The generated files are written to the current directory.

Options:

`

var tagsByTarget = map[string]string{
	"bpf":   "",
	"bpfel": "386 amd64 amd64p32 arm arm64 mipsle mips64le mips64p32le ppc64le riscv64",
	"bpfeb": "armbe arm64be mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64",
}

func run(stdout io.Writer, pkg, outputDir string, args []string) (err error) {
	b2g := bpf2go{
		stdout:    stdout,
		pkg:       pkg,
		outputDir: outputDir,
	}

	fs := flag.NewFlagSet("bpf2go", flag.ContinueOnError)
	fs.StringVar(&b2g.cc, "cc", "clang", "`binary` used to compile C to BPF")
	flagCFlags := fs.String("cflags", "", "flags passed to the compiler, may contain quoted arguments")
	fs.StringVar(&b2g.tags, "tags", "", "list of Go build tags to include in generated files")
	flagTarget := fs.String("target", "bpfel,bpfeb", "clang target to compile for (bpf, bpfel, bpfeb)")
	fs.StringVar(&b2g.makeBase, "makebase", "", "write make compatible depinfo files relative to `directory`")

	fs.SetOutput(stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), helpText, fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if b2g.pkg == "" {
		return errors.New("missing package, are you running via go generate?")
	}

	if b2g.cc == "" {
		return errors.New("no compiler specified")
	}

	args, cFlags := splitCFlagsFromArgs(fs.Args())

	if *flagCFlags != "" {
		splitCFlags, err := splitArguments(*flagCFlags)
		if err != nil {
			return err
		}

		// Command line arguments take precedence over C flags
		// from the flag.
		cFlags = append(splitCFlags, cFlags...)
	}

	for _, cFlag := range cFlags {
		if strings.HasPrefix(cFlag, "-M") {
			return fmt.Errorf("use -makebase instead of %q", cFlag)
		}
	}

	b2g.cFlags = cFlags[:len(cFlags):len(cFlags)]

	if len(args) < 2 {
		return errors.New("expected at least two arguments")
	}

	b2g.ident = args[0]
	if !token.IsIdentifier(b2g.ident) {
		return fmt.Errorf("%q is not a valid identifier", b2g.ident)
	}

	input := args[1]
	if _, err := os.Stat(input); os.IsNotExist(err) {
		return fmt.Errorf("file %s doesn't exist", input)
	} else if err != nil {
		return fmt.Errorf("state %s: %s", input, err)
	}

	b2g.sourceFile, err = filepath.Abs(input)
	if err != nil {
		return err
	}

	if b2g.makeBase != "" {
		b2g.makeBase, err = filepath.Abs(b2g.makeBase)
		if err != nil {
			return err
		}
	}

	if strings.ContainsRune(b2g.tags, '\n') {
		return fmt.Errorf("-tags mustn't contain new line characters")
	}

	targets := strings.Split(*flagTarget, ",")
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	for _, target := range targets {
		if err := b2g.convert(target); err != nil {
			return err
		}
	}

	return nil
}

type bpf2go struct {
	stdout io.Writer
	// Absolute path to a .c file.
	sourceFile string
	// Absolute path to a directory where .go are written
	outputDir string
	// Valid go package name.
	pkg string
	// Valid go identifier.
	ident string
	// C compiler.
	cc string
	// C flags passed to the compiler.
	cFlags []string
	// Go tags included in the .go
	tags string
	// Base directory of the Makefile. Enables outputting make-style dependencies
	// in .d files.
	makeBase string
}

func (b2g *bpf2go) convert(target string) (err error) {
	removeOnError := func(f *os.File) {
		if err != nil {
			os.Remove(f.Name())
		}
		f.Close()
	}

	stem := fmt.Sprintf("%s_%s", strings.ToLower(b2g.ident), target)
	objFileName := filepath.Join(b2g.outputDir, stem+".o")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	var tags []string
	targetTags, ok := tagsByTarget[target]
	if !ok {
		return fmt.Errorf("unsupported target %q", target)
	} else if targetTags != "" {
		tags = append(tags, targetTags)
	}

	if b2g.tags != "" {
		tags = append(tags, b2g.tags)
	}

	var dep bytes.Buffer
	err = compile(compileArgs{
		cc:     b2g.cc,
		cFlags: b2g.cFlags,
		target: target,
		dir:    cwd,
		source: b2g.sourceFile,
		dest:   objFileName,
		dep:    &dep,
	})
	if err != nil {
		return err
	}

	fmt.Fprintln(b2g.stdout, "Compiled", objFileName)

	// Write out generated go
	goFileName := filepath.Join(b2g.outputDir, stem+".go")
	goFile, err := os.Create(goFileName)
	if err != nil {
		return err
	}
	defer removeOnError(goFile)

	obj, err := os.Open(objFileName)
	if err != nil {
		return err
	}
	defer obj.Close()

	err = writeCommon(writeArgs{
		pkg:   b2g.pkg,
		ident: b2g.ident,
		tags:  tags,
		obj:   objFileName,
		out:   goFile,
	})
	if err != nil {
		return fmt.Errorf("can't write %s: %s", goFileName, err)
	}

	fmt.Fprintln(b2g.stdout, "Wrote", goFileName)

	if b2g.makeBase == "" {
		return
	}

	deps, err := parseDependencies(cwd, &dep)
	if err != nil {
		return fmt.Errorf("can't read dependency information: %s", err)
	}

	// There is always at least a dependency for the main file.
	deps[0].file = goFileName
	depFile, err := adjustDependencies(b2g.makeBase, deps)
	if err != nil {
		return fmt.Errorf("can't adjust dependency information: %s", err)
	}

	depFileName := goFileName + ".d"
	if err := ioutil.WriteFile(depFileName, depFile, 0666); err != nil {
		return fmt.Errorf("can't write dependency file: %s", err)
	}

	fmt.Fprintln(b2g.stdout, "Wrote", depFileName)
	return nil
}

func main() {
	outputDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if err := run(os.Stdout, os.Getenv("GOPACKAGE"), outputDir, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
