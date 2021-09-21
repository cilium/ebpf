package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
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

// Targets understood by bpf2go.
//
// Targets without a Linux string can't be used directly and are only included
// for the generic bpf, bpfel, bpfeb targets.
var targetByGoArch = map[string]target{
	"386":         {"bpfel", "x86"},
	"amd64":       {"bpfel", "x86"},
	"amd64p32":    {"bpfel", ""},
	"arm":         {"bpfel", "arm"},
	"arm64":       {"bpfel", "arm64"},
	"mipsle":      {"bpfel", ""},
	"mips64le":    {"bpfel", ""},
	"mips64p32le": {"bpfel", ""},
	"ppc64le":     {"bpfel", "powerpc"},
	"riscv64":     {"bpfel", ""},
	"armbe":       {"bpfeb", "arm"},
	"arm64be":     {"bpfeb", "arm64"},
	"mips":        {"bpfeb", ""},
	"mips64":      {"bpfeb", ""},
	"mips64p32":   {"bpfeb", ""},
	"ppc64":       {"bpfeb", "powerpc"},
	"s390":        {"bpfeb", "s390"},
	"s390x":       {"bpfeb", "s390"},
	"sparc":       {"bpfeb", "sparc"},
	"sparc64":     {"bpfeb", "sparc"},
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
	flagTarget := fs.String("target", "bpfel,bpfeb", "clang target to compile for")
	fs.StringVar(&b2g.makeBase, "makebase", "", "write make compatible depinfo files relative to `directory`")

	fs.SetOutput(stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), helpText, fs.Name())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output())
		printTargets(fs.Output())
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

	targetArches := strings.Split(*flagTarget, ",")
	if len(targetArches) == 0 {
		return fmt.Errorf("no targets specified")
	}

	targets, err := collectTargets(targetArches)
	if errors.Is(err, errInvalidTarget) {
		printTargets(stdout)
		fmt.Fprintln(stdout)
		return err
	}
	if err != nil {
		return err
	}

	for target, arches := range targets {
		if err := b2g.convert(target, arches); err != nil {
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

func (b2g *bpf2go) convert(tgt target, arches []string) (err error) {
	removeOnError := func(f *os.File) {
		if err != nil {
			os.Remove(f.Name())
		}
		f.Close()
	}

	stem := fmt.Sprintf("%s_%s", strings.ToLower(b2g.ident), tgt.clang)
	if tgt.linux != "" {
		stem = fmt.Sprintf("%s_%s_%s", strings.ToLower(b2g.ident), tgt.clang, tgt.linux)
	}

	objFileName := filepath.Join(b2g.outputDir, stem+".o")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	var tags []string
	if len(arches) > 0 {
		tags = append(tags, strings.Join(arches, " "))
	}
	if b2g.tags != "" {
		tags = append(tags, b2g.tags)
	}

	cFlags := make([]string, len(b2g.cFlags))
	copy(cFlags, b2g.cFlags)
	if tgt.linux != "" {
		cFlags = append(cFlags, "-D__TARGET_ARCH_"+tgt.linux)
	}

	var dep bytes.Buffer
	err = compile(compileArgs{
		cc:     b2g.cc,
		cFlags: cFlags,
		target: tgt.clang,
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
	if err := os.WriteFile(depFileName, depFile, 0666); err != nil {
		return fmt.Errorf("can't write dependency file: %s", err)
	}

	fmt.Fprintln(b2g.stdout, "Wrote", depFileName)
	return nil
}

type target struct {
	clang string
	linux string
}

func printTargets(w io.Writer) {
	var arches []string
	for arch, archTarget := range targetByGoArch {
		if archTarget.linux == "" {
			continue
		}
		arches = append(arches, arch)
	}
	sort.Strings(arches)

	fmt.Fprint(w, "Supported targets:\n")
	fmt.Fprint(w, "\tbpf\n\tbpfel\n\tbpfeb\n")
	for _, arch := range arches {
		fmt.Fprintf(w, "\t%s\n", arch)
	}
}

var errInvalidTarget = errors.New("unsupported target")

func collectTargets(targets []string) (map[target][]string, error) {
	result := make(map[target][]string)
	for _, tgt := range targets {
		switch tgt {
		case "bpf", "bpfel", "bpfeb":
			var goarches []string
			for arch, archTarget := range targetByGoArch {
				if archTarget.clang == tgt {
					// Include tags for all goarches that have the same endianness.
					goarches = append(goarches, arch)
				}
			}
			sort.Strings(goarches)
			result[target{tgt, ""}] = goarches

		default:
			archTarget, ok := targetByGoArch[tgt]
			if !ok || archTarget.linux == "" {
				return nil, fmt.Errorf("%q: %w", tgt, errInvalidTarget)
			}

			var goarches []string
			for goarch, lt := range targetByGoArch {
				if lt == archTarget {
					// Include tags for all goarches that have the same
					// target.
					goarches = append(goarches, goarch)
				}
			}

			sort.Strings(goarches)
			result[archTarget] = goarches
		}
	}

	return result, nil
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
