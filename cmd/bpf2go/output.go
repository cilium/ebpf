package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/token"
	"io"
	"sort"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
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

func (n templateName) Programs() string {
	return string(n) + "Programs"
}

func (n templateName) CloseHelper() string {
	return "_" + toUpperFirst(string(n)) + "Close"
}

type outputArgs struct {
	// Package of the resulting file.
	pkg string
	// The prefix of all names declared at the top-level.
	stem string
	// Build tags included in the resulting file.
	tags []string
	// Maps to be emitted.
	maps []string
	// Programs to be emitted.
	programs []string
	// Types to be emitted.
	types []btf.Type
	// Filename of the ELF object to embed.
	obj string
	out io.Writer
}

func output(args outputArgs) error {
	maps := make(map[string]string)
	for _, name := range args.maps {
		maps[name] = internal.Identifier(name)
	}

	programs := make(map[string]string)
	for _, name := range args.programs {
		programs[name] = internal.Identifier(name)
	}

	typeNames := make(map[btf.Type]string)
	for _, typ := range args.types {
		typeNames[typ] = args.stem + internal.Identifier(typ.TypeName())
	}

	// Ensure we don't have conflicting names and generate a sorted list of
	// named types so that the output is stable.
	types, err := sortTypes(typeNames)
	if err != nil {
		return err
	}

	module, err := currentModule()
	if err != nil {
		return err
	}

	gf := &btf.GoFormatter{
		Names:      typeNames,
		Identifier: internal.Identifier,
	}

	ctx := struct {
		*btf.GoFormatter
		Module    string
		Package   string
		Tags      []string
		Name      templateName
		Maps      map[string]string
		Programs  map[string]string
		Types     []btf.Type
		TypeNames map[btf.Type]string
		File      string
	}{
		gf,
		module,
		args.pkg,
		args.tags,
		templateName(args.stem),
		maps,
		programs,
		types,
		typeNames,
		args.obj,
	}

	var buf bytes.Buffer
	if err := commonTemplate.Execute(&buf, &ctx); err != nil {
		return fmt.Errorf("can't generate types: %s", err)
	}

	return internal.WriteFormatted(buf.Bytes(), args.out)
}

func collectCTypes(types *btf.Spec, names []string) ([]btf.Type, error) {
	var result []btf.Type
	for _, cType := range names {
		typ, err := types.AnyTypeByName(cType)
		if err != nil {
			return nil, err
		}
		result = append(result, typ)
	}
	return result, nil
}

// collectMapTypes returns a list of all types used as map keys or values.
func collectMapTypes(maps map[string]*ebpf.MapSpec) []btf.Type {
	var result []btf.Type
	for _, m := range maps {
		if m.Key != nil && m.Key.TypeName() != "" {
			result = append(result, m.Key)
		}

		if m.Value != nil && m.Value.TypeName() != "" {
			result = append(result, m.Value)
		}
	}
	return result
}

// sortTypes returns a list of types sorted by their (generated) Go type name.
//
// Duplicate Go type names are rejected.
func sortTypes(typeNames map[btf.Type]string) ([]btf.Type, error) {
	var types []btf.Type
	var names []string
	for typ, name := range typeNames {
		i := sort.SearchStrings(names, name)
		if i >= len(names) {
			types = append(types, typ)
			names = append(names, name)
			continue
		}

		if names[i] == name {
			return nil, fmt.Errorf("type name %q is used multiple times", name)
		}

		types = append(types[:i], append([]btf.Type{typ}, types[i:]...)...)
		names = append(names[:i], append([]string{name}, names[i:]...)...)
	}

	return types, nil
}
