package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/build/constraint"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
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

Some options take defaults from the environment. Variable name is mentioned
next to the respective option.

Options:

`

// Targets understood by bpf2go.
//
// Targets without a Linux string can't be used directly and are only included
// for the generic bpf, bpfel, bpfeb targets.
//
// See https://go.dev/doc/install/source#environment for valid GOARCHes when
// GOOS=linux.
var targetByGoArch = map[goarch]target{
	"386":      {"bpfel", "x86"},
	"amd64":    {"bpfel", "x86"},
	"arm":      {"bpfel", "arm"},
	"arm64":    {"bpfel", "arm64"},
	"loong64":  {"bpfel", "loongarch"},
	"mips":     {"bpfeb", "mips"},
	"mipsle":   {"bpfel", ""},
	"mips64":   {"bpfeb", ""},
	"mips64le": {"bpfel", ""},
	"ppc64":    {"bpfeb", "powerpc"},
	"ppc64le":  {"bpfel", "powerpc"},
	"riscv64":  {"bpfel", "riscv"},
	"s390x":    {"bpfeb", "s390"},
}

func run(stdout io.Writer, args []string) (err error) {
	b2g, err := newB2G(stdout, args)
	switch {
	case err == nil:
		return b2g.convertAll()
	case errors.Is(err, flag.ErrHelp):
		return nil
	default:
		return err
	}
}

type bpf2go struct {
	stdout io.Writer
	// Absolute path to a .c file.
	sourceFile string
	// Absolute path to a directory where .go are written
	outputDir string
	// Alternative output stem. If empty, identStem is used.
	outputStem string
	// Valid go package name.
	pkg string
	// Valid go identifier.
	identStem string
	// Targets to build for.
	targetArches map[target][]goarch
	// C compiler.
	cc string
	// Command used to strip DWARF.
	strip            string
	disableStripping bool
	// C flags passed to the compiler.
	cFlags          []string
	skipGlobalTypes bool
	// C types to include in the generated output.
	cTypes cTypes
	// Build tags to be included in the output.
	tags buildTags
	// Base directory of the Makefile. Enables outputting make-style dependencies
	// in .d files.
	makeBase string
}

func newB2G(stdout io.Writer, args []string) (*bpf2go, error) {
	b2g := &bpf2go{
		stdout: stdout,
	}

	fs := flag.NewFlagSet("bpf2go", flag.ContinueOnError)
	fs.StringVar(&b2g.cc, "cc", getEnv("BPF2GO_CC", "clang"),
		"`binary` used to compile C to BPF ($BPF2GO_CC)")
	fs.StringVar(&b2g.strip, "strip", getEnv("BPF2GO_STRIP", ""),
		"`binary` used to strip DWARF from compiled BPF ($BPF2GO_STRIP)")
	fs.BoolVar(&b2g.disableStripping, "no-strip", false, "disable stripping of DWARF")
	flagCFlags := fs.String("cflags", getEnv("BPF2GO_CFLAGS", ""),
		"flags passed to the compiler, may contain quoted arguments ($BPF2GO_CFLAGS)")
	fs.Var(&b2g.tags, "tags", "Comma-separated list of Go build tags to include in generated files")
	flagTarget := fs.String("target", "bpfel,bpfeb", "clang target(s) to compile for (comma separated)")
	fs.StringVar(&b2g.makeBase, "makebase", getEnv("BPF2GO_MAKEBASE", ""),
		"write make compatible depinfo files relative to `directory` ($BPF2GO_MAKEBASE)")
	fs.Var(&b2g.cTypes, "type", "`Name` of a type to generate a Go declaration for, may be repeated")
	fs.BoolVar(&b2g.skipGlobalTypes, "no-global-types", false, "Skip generating types for map keys and values, etc.")
	fs.StringVar(&b2g.outputStem, "output-stem", "", "alternative stem for names of generated files (defaults to ident)")
	outDir := fs.String("output-dir", "", "target directory of generated files (defaults to current directory)")
	outPkg := fs.String("go-package", "", "package for output go file (default as ENV GOPACKAGE)")
	fs.SetOutput(b2g.stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), helpText, fs.Name())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output())
		printTargets(fs.Output())
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *outDir == "" {
		var err error
		if *outDir, err = os.Getwd(); err != nil {
			return nil, err
		}
	}
	b2g.outputDir = *outDir

	if *outPkg == "" {
		*outPkg = os.Getenv(gopackageEnv)
	}
	b2g.pkg = *outPkg

	if b2g.pkg == "" {
		return nil, errors.New("missing package, you should either set the go-package flag or the GOPACKAGE env")
	}

	if b2g.cc == "" {
		return nil, errors.New("no compiler specified")
	}

	args, cFlags := splitCFlagsFromArgs(fs.Args())

	if *flagCFlags != "" {
		splitCFlags, err := splitArguments(*flagCFlags)
		if err != nil {
			return nil, err
		}

		// Command line arguments take precedence over C flags
		// from the flag.
		cFlags = append(splitCFlags, cFlags...)
	}

	for _, cFlag := range cFlags {
		if strings.HasPrefix(cFlag, "-M") {
			return nil, fmt.Errorf("use -makebase instead of %q", cFlag)
		}
	}

	b2g.cFlags = cFlags[:len(cFlags):len(cFlags)]

	if len(args) < 2 {
		return nil, errors.New("expected at least two arguments")
	}

	b2g.identStem = args[0]
	if !token.IsIdentifier(b2g.identStem) {
		return nil, fmt.Errorf("%q is not a valid identifier", b2g.identStem)
	}

	sourceFile, err := filepath.Abs(args[1])
	if err != nil {
		return nil, err
	}
	b2g.sourceFile = sourceFile

	if b2g.makeBase != "" {
		b2g.makeBase, err = filepath.Abs(b2g.makeBase)
		if err != nil {
			return nil, err
		}
	}

	if b2g.outputStem != "" && strings.ContainsRune(b2g.outputStem, filepath.Separator) {
		return nil, fmt.Errorf("-output-stem %q must not contain path separation characters", b2g.outputStem)
	}

	targetArches, err := collectTargets(strings.Split(*flagTarget, ","))
	if errors.Is(err, errInvalidTarget) {
		printTargets(b2g.stdout)
		fmt.Fprintln(b2g.stdout)
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	if len(targetArches) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}
	b2g.targetArches = targetArches

	// Try to find a suitable llvm-strip, possibly with a version suffix derived
	// from the clang binary.
	if b2g.strip == "" {
		b2g.strip = "llvm-strip"
		if strings.HasPrefix(b2g.cc, "clang") {
			b2g.strip += strings.TrimPrefix(b2g.cc, "clang")
		}
	}

	return b2g, nil
}

// cTypes collects the C type names a user wants to generate Go types for.
//
// Names are guaranteed to be unique, and only a subset of names is accepted so
// that we may extend the flag syntax in the future.
type cTypes []string

var _ flag.Value = (*cTypes)(nil)

func (ct *cTypes) String() string {
	if ct == nil {
		return "[]"
	}
	return fmt.Sprint(*ct)
}

const validCTypeChars = `[a-z0-9_]`

var reValidCType = regexp.MustCompile(`(?i)^` + validCTypeChars + `+$`)

func (ct *cTypes) Set(value string) error {
	if !reValidCType.MatchString(value) {
		return fmt.Errorf("%q contains characters outside of %s", value, validCTypeChars)
	}

	i := sort.SearchStrings(*ct, value)
	if i >= len(*ct) {
		*ct = append(*ct, value)
		return nil
	}

	if (*ct)[i] == value {
		return fmt.Errorf("duplicate type %q", value)
	}

	*ct = append((*ct)[:i], append([]string{value}, (*ct)[i:]...)...)
	return nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func (b2g *bpf2go) convertAll() (err error) {
	if _, err := os.Stat(b2g.sourceFile); os.IsNotExist(err) {
		return fmt.Errorf("file %s doesn't exist", b2g.sourceFile)
	} else if err != nil {
		return err
	}

	if !b2g.disableStripping {
		b2g.strip, err = exec.LookPath(b2g.strip)
		if err != nil {
			return err
		}
	}

	for target, arches := range b2g.targetArches {
		if err := b2g.convert(target, arches); err != nil {
			return err
		}
	}

	return nil
}

func (b2g *bpf2go) convert(tgt target, goarches []goarch) (err error) {
	removeOnError := func(f *os.File) {
		if err != nil {
			os.Remove(f.Name())
		}
		f.Close()
	}

	outputStem := b2g.outputStem
	if outputStem == "" {
		outputStem = strings.ToLower(b2g.identStem)
	}

	// The output filename must not match any of the following patterns:
	//
	//     *_GOOS
	//     *_GOARCH
	//     *_GOOS_GOARCH
	//
	// Otherwise it is interpreted as a build constraint by the Go toolchain.
	stem := fmt.Sprintf("%s_%s", outputStem, tgt.clang)
	if tgt.linux != "" {
		stem = fmt.Sprintf("%s_%s_%s", outputStem, tgt.linux, tgt.clang)
	}

	absOutPath, err := filepath.Abs(b2g.outputDir)
	if err != nil {
		return err
	}

	objFileName := filepath.Join(absOutPath, stem+".o")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	var archConstraint constraint.Expr
	for _, goarch := range goarches {
		tag := &constraint.TagExpr{Tag: string(goarch)}
		archConstraint = orConstraints(archConstraint, tag)
	}

	constraints := andConstraints(archConstraint, b2g.tags.Expr)

	cFlags := make([]string, len(b2g.cFlags))
	copy(cFlags, b2g.cFlags)
	if tgt.linux != "" {
		cFlags = append(cFlags, "-D__TARGET_ARCH_"+tgt.linux)
	}

	if err := b2g.removeOldOutputFiles(outputStem, tgt); err != nil {
		return fmt.Errorf("remove obsolete output: %w", err)
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

	if !b2g.disableStripping {
		if err := strip(b2g.strip, objFileName); err != nil {
			return err
		}
		fmt.Fprintln(b2g.stdout, "Stripped", objFileName)
	}

	spec, err := ebpf.LoadCollectionSpec(objFileName)
	if err != nil {
		return fmt.Errorf("can't load BPF from ELF: %s", err)
	}

	maps, programs, types, err := collectFromSpec(spec, b2g.cTypes, b2g.skipGlobalTypes)
	if err != nil {
		return err
	}

	// Write out generated go
	goFileName := filepath.Join(absOutPath, stem+".go")
	goFile, err := os.Create(goFileName)
	if err != nil {
		return err
	}
	defer removeOnError(goFile)

	err = output(outputArgs{
		pkg:         b2g.pkg,
		stem:        b2g.identStem,
		constraints: constraints,
		maps:        maps,
		programs:    programs,
		types:       types,
		obj:         filepath.Base(objFileName),
		out:         goFile,
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

// removeOldOutputFiles removes output files generated by an old naming scheme.
//
// In the old scheme some linux targets were interpreted as build constraints
// by the go toolchain.
func (b2g *bpf2go) removeOldOutputFiles(outputStem string, tgt target) error {
	if tgt.linux == "" {
		return nil
	}

	stem := fmt.Sprintf("%s_%s_%s", outputStem, tgt.clang, tgt.linux)
	for _, ext := range []string{".o", ".go"} {
		filename := filepath.Join(b2g.outputDir, stem+ext)

		if err := os.Remove(filename); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}

		fmt.Fprintln(b2g.stdout, "Removed obsolete", filename)
	}

	return nil
}

type target struct {
	// Clang arch string, used to define the clang -target flag, as per
	// "clang -print-targets".
	clang string
	// Linux arch string, used to define __TARGET_ARCH_xzy macros used by
	// https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h
	linux string
}

type goarch string

func printTargets(w io.Writer) {
	var arches []string
	for goarch, archTarget := range targetByGoArch {
		if archTarget.linux == "" {
			continue
		}
		arches = append(arches, string(goarch))
	}
	sort.Strings(arches)

	fmt.Fprint(w, "Supported targets:\n")
	fmt.Fprint(w, "\tbpf\n\tbpfel\n\tbpfeb\n")
	for _, arch := range arches {
		fmt.Fprintf(w, "\t%s\n", arch)
	}
}

var errInvalidTarget = errors.New("unsupported target")

func collectTargets(targets []string) (map[target][]goarch, error) {
	result := make(map[target][]goarch)
	for _, tgt := range targets {
		switch tgt {
		case "bpf", "bpfel", "bpfeb":
			var goarches []goarch
			for arch, archTarget := range targetByGoArch {
				if archTarget.clang == tgt {
					// Include tags for all goarches that have the same endianness.
					goarches = append(goarches, arch)
				}
			}
			slices.Sort(goarches)
			result[target{tgt, ""}] = goarches

		case "native":
			tgt = runtime.GOARCH
			fallthrough

		default:
			archTarget, ok := targetByGoArch[goarch(tgt)]
			if !ok || archTarget.linux == "" {
				return nil, fmt.Errorf("%q: %w", tgt, errInvalidTarget)
			}

			var goarches []goarch
			for goarch, lt := range targetByGoArch {
				if lt == archTarget {
					// Include tags for all goarches that have the same
					// target.
					goarches = append(goarches, goarch)
				}
			}

			slices.Sort(goarches)
			result[archTarget] = goarches
		}
	}

	return result, nil
}

const gopackageEnv = "GOPACKAGE"

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
