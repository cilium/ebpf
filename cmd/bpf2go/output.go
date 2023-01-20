package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
)

//go:embed template.tpl
var commonRaw string

var (
	tplFuncs = map[string]interface{}{
		"tag": tag,
	}
	commonTemplate = template.Must(template.New("common").Funcs(tplFuncs).Parse(commonRaw))
)

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
	pkg             string
	ident           string
	tags            []string
	cTypes          []string
	skipGlobalTypes bool
	obj             string
	out             io.Writer
}

func output(args outputArgs) error {
	obj, err := os.ReadFile(args.obj)
	if err != nil {
		return fmt.Errorf("read object file contents: %s", err)
	}

	rd := bytes.NewReader(obj)
	spec, err := ebpf.LoadCollectionSpecFromReader(rd)
	if err != nil {
		return fmt.Errorf("can't load BPF from ELF: %s", err)
	}

	maps := make(map[string]string)
	for name := range spec.Maps {
		if strings.HasPrefix(name, ".") {
			// Skip .rodata, .data, .bss, etc. sections
			continue
		}

		maps[name] = internal.Identifier(name)
	}

	programs := make(map[string]string)
	for name := range spec.Programs {
		programs[name] = internal.Identifier(name)
	}

	// Collect any types which we've been asked for explicitly.
	cTypes, err := collectCTypes(spec.Types, args.cTypes)
	if err != nil {
		return err
	}

	typeNames := make(map[btf.Type]string)
	for _, cType := range cTypes {
		typeNames[cType] = args.ident + internal.Identifier(cType.TypeName())
	}

	// Collect map key and value types, unless we've been asked not to.
	if !args.skipGlobalTypes {
		for _, typ := range collectMapTypes(spec.Maps) {
			switch btf.UnderlyingType(typ).(type) {
			case *btf.Datasec:
				// Avoid emitting .rodata, .bss, etc. for now. We might want to
				// name these types differently, etc.
				continue

			case *btf.Int:
				// Don't emit primitive types by default.
				continue
			}

			typeNames[typ] = args.ident + internal.Identifier(typ.TypeName())
		}
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
		templateName(args.ident),
		maps,
		programs,
		types,
		typeNames,
		filepath.Base(args.obj),
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

func tag(str string) string {
	return "`ebpf:\"" + str + "\"`"
}
