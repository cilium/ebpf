package gen

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/build/constraint"
	"go/token"
	"io"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/cilium/ebpf/btf"
	b2gInt "github.com/cilium/ebpf/cmd/bpf2go/internal"
	"github.com/cilium/ebpf/internal"
)

//go:embed output.tpl
var commonRaw string

var commonTemplate = template.Must(template.New("common").Parse(commonRaw))

type templateName string

func (n templateName) maybeExport(str string) string {
	if token.IsExported(string(n)) {
		return toUpperFirst(str)
	}

	return str
}

func (n templateName) Bytes() string {
	return "_" + toUpperFirst(string(n)) + "Bytes"
}

func (n templateName) Specs() string {
	return string(n) + "Specs"
}

func (n templateName) ProgramSpecs() string {
	return string(n) + "ProgramSpecs"
}

func (n templateName) MapSpecs() string {
	return string(n) + "MapSpecs"
}

func (n templateName) VariableSpecs() string {
	return string(n) + "VariableSpecs"
}

func (n templateName) Load() string {
	return n.maybeExport("load" + toUpperFirst(string(n)))
}

func (n templateName) LoadObjects() string {
	return n.maybeExport("load" + toUpperFirst(string(n)) + "Objects")
}

func (n templateName) Objects() string {
	return string(n) + "Objects"
}

func (n templateName) Maps() string {
	return string(n) + "Maps"
}

func (n templateName) Variables() string {
	return string(n) + "Variables"
}

func (n templateName) Programs() string {
	return string(n) + "Programs"
}

func (n templateName) CloseHelper() string {
	return "_" + toUpperFirst(string(n)) + "Close"
}

type GenerateArgs struct {
	// Package of the resulting file.
	Package string
	// The prefix of all names declared at the top-level.
	Stem string
	// Build Constraints included in the resulting file.
	Constraints constraint.Expr
	// Maps to be emitted.
	Maps []string
	// Variables to be emitted.
	Variables []string
	// Programs to be emitted.
	Programs []string
	// Types to be emitted.
	Types []btf.Type
	// Filename of the object to embed.
	ObjectFile string
	// Output to write template to.
	Output io.Writer
	// Function which transforms the input into a valid go identifier. Uses the default behaviour if nil
	Identifier func(string) string
}

// Generate bindings for a BPF ELF file.
func Generate(args GenerateArgs) error {
	if args.Identifier == nil {
		args.Identifier = internal.Identifier
	}
	if !token.IsIdentifier(args.Stem) {
		return fmt.Errorf("%q is not a valid identifier", args.Stem)
	}

	if strings.ContainsAny(args.ObjectFile, "\n") {
		// Prevent injecting newlines into the template.
		return fmt.Errorf("file %q contains an invalid character", args.ObjectFile)
	}

	for _, typ := range args.Types {
		if _, ok := btf.As[*btf.Datasec](typ); ok {
			// Avoid emitting .rodata, .bss, etc. for now. We might want to
			// name these types differently, etc.
			return fmt.Errorf("can't output btf.Datasec: %s", typ)
		}
	}

	maps := make(map[string]string)
	for _, name := range args.Maps {
		maps[name] = args.Identifier(name)
	}

	variables := make(map[string]string)
	for _, name := range args.Variables {
		variables[name] = args.Identifier(name)
	}

	programs := make(map[string]string)
	for _, name := range args.Programs {
		programs[name] = args.Identifier(name)
	}

	tn := templateName(args.Stem)
	reservedNames := map[string]struct{}{
		tn.Specs():         {},
		tn.MapSpecs():      {},
		tn.ProgramSpecs():  {},
		tn.VariableSpecs(): {},
		tn.Objects():       {},
		tn.Maps():          {},
		tn.Programs():      {},
		tn.Variables():     {},
	}

	typeByName := map[string]btf.Type{}
	nameByType := map[btf.Type]string{}
	for _, typ := range args.Types {
		// NB: This also deduplicates types.
		name := args.Stem + args.Identifier(typ.TypeName())
		if _, reserved := reservedNames[name]; reserved {
			return fmt.Errorf("type name %q is reserved", name)
		}
		if otherType, ok := typeByName[name]; ok {
			if otherType == typ {
				continue
			}
			return fmt.Errorf("type name %q is used multiple times", name)
		}
		typeByName[name] = typ
		nameByType[typ] = name
	}

	gf := &btf.GoFormatter{
		Names:      nameByType,
		Identifier: args.Identifier,
		ShortEnumIdentifier: func(_, element string) string {
			elementName := args.Stem + args.Identifier(element)
			if _, nameTaken := typeByName[elementName]; nameTaken {
				return ""
			}
			if _, nameReserved := reservedNames[elementName]; nameReserved {
				return ""
			}
			reservedNames[elementName] = struct{}{}
			return elementName
		},
	}

	ctx := struct {
		*btf.GoFormatter
		Module      string
		Package     string
		Constraints constraint.Expr
		Name        templateName
		Maps        map[string]string
		Variables   map[string]string
		Programs    map[string]string
		Types       map[string]btf.Type
		File        string
	}{
		gf,
		b2gInt.CurrentModule,
		args.Package,
		args.Constraints,
		templateName(args.Stem),
		maps,
		variables,
		programs,
		typeByName,
		args.ObjectFile,
	}

	var buf bytes.Buffer
	if err := commonTemplate.Execute(&buf, &ctx); err != nil {
		return fmt.Errorf("can't generate types: %v", err)
	}

	return internal.WriteFormatted(buf.Bytes(), args.Output)
}

func toUpperFirst(str string) string {
	first, n := utf8.DecodeRuneInString(str)
	return string(unicode.ToUpper(first)) + str[n:]
}
