package main

import (
	"bytes"
	"fmt"
	"go/token"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

const ebpfModule = "github.com/cilium/ebpf"

const commonRaw = `// Code generated by bpf2go; DO NOT EDIT.
{{- range .Tags }}
// +build {{ . }}
{{- end }}

package {{ .Package }}

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"{{ .Module }}"
)

// {{ .Name.Load }} returns the embedded CollectionSpec for {{ .Name }}.
func {{ .Name.Load }}() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader({{ .Name.Bytes }})
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load {{ .Name }}: %w", err)
	}

	return spec, err
}

// {{ .Name.LoadObjects }} loads {{ .Name }} and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *{{ .Name.Objects }}
//     *{{ .Name.Programs }}
//     *{{ .Name.Maps }}
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func {{ .Name.LoadObjects }}(obj interface{}, opts *ebpf.CollectionOptions) (error) {
	spec, err := {{ .Name.Load }}()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// {{ .Name.Specs }} contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type {{ .Name.Specs }} struct {
	{{ .Name.ProgramSpecs }}
	{{ .Name.MapSpecs }}
}

// {{ .Name.Specs }} contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type {{ .Name.ProgramSpecs }} struct {
{{- range $name, $id := .Programs }}
	{{ $id }} *ebpf.ProgramSpec {{ tag $name }}
{{- end }}
}

// {{ .Name.MapSpecs }} contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type {{ .Name.MapSpecs }} struct {
{{- range $name, $id := .Maps }}
	{{ $id }} *ebpf.MapSpec {{ tag $name }}
{{- end }}
}

// {{ .Name.Objects }} contains all objects after they have been loaded into the kernel.
//
// It can be passed to {{ .Name.LoadObjects }} or ebpf.CollectionSpec.LoadAndAssign.
type {{ .Name.Objects }} struct {
	{{ .Name.Programs }}
	{{ .Name.Maps }}
}

func (o *{{ .Name.Objects }}) Close() error {
	return {{ .Name.CloseHelper }}(
		&o.{{ .Name.Programs }},
		&o.{{ .Name.Maps }},
	)
}

// {{ .Name.Maps }} contains all maps after they have been loaded into the kernel.
//
// It can be passed to {{ .Name.LoadObjects }} or ebpf.CollectionSpec.LoadAndAssign.
type {{ .Name.Maps }} struct {
{{- range $name, $id := .Maps }}
	{{ $id }} *ebpf.Map {{ tag $name }}
{{- end }}
}

func (m *{{ .Name.Maps }}) Close() error {
	return {{ .Name.CloseHelper }}(
{{- range $id := .Maps }}
		m.{{ $id }},
{{- end }}
	)
}

// {{ .Name.Programs }} contains all programs after they have been loaded into the kernel.
//
// It can be passed to {{ .Name.LoadObjects }} or ebpf.CollectionSpec.LoadAndAssign.
type {{ .Name.Programs }} struct {
{{- range $name, $id := .Programs }}
	{{ $id }} *ebpf.Program {{ tag $name }}
{{- end }}
}

func (p *{{ .Name.Programs }}) Close() error {
	return {{ .Name.CloseHelper }}(
{{- range $id := .Programs }}
		p.{{ $id }},
{{- end }}
	)
}

func {{ .Name.CloseHelper }}(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed {{ .File }}
var {{ .Name.Bytes }} []byte

`

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
	return n.maybeExport(string(n) + "Specs")
}

func (n templateName) ProgramSpecs() string {
	return n.maybeExport(string(n) + "ProgramSpecs")
}

func (n templateName) MapSpecs() string {
	return n.maybeExport(string(n) + "MapSpecs")
}

func (n templateName) Load() string {
	return n.maybeExport("load" + toUpperFirst(string(n)))
}

func (n templateName) LoadObjects() string {
	return n.maybeExport("load" + toUpperFirst(string(n)) + "Objects")
}

func (n templateName) Objects() string {
	return n.maybeExport(string(n) + "Objects")
}

func (n templateName) Maps() string {
	return n.maybeExport(string(n) + "Maps")
}

func (n templateName) Programs() string {
	return n.maybeExport(string(n) + "Programs")
}

func (n templateName) CloseHelper() string {
	return "_" + toUpperFirst(string(n)) + "Close"
}

type writeArgs struct {
	pkg   string
	ident string
	tags  []string
	obj   string
	out   io.Writer
}

func writeCommon(args writeArgs) error {
	obj, err := ioutil.ReadFile(args.obj)
	if err != nil {
		return fmt.Errorf("read object file contents: %s", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
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

	ctx := struct {
		Module   string
		Package  string
		Tags     []string
		Name     templateName
		Maps     map[string]string
		Programs map[string]string
		File     string
	}{
		ebpfModule,
		args.pkg,
		args.tags,
		templateName(args.ident),
		maps,
		programs,
		filepath.Base(args.obj),
	}

	var buf bytes.Buffer
	if err := commonTemplate.Execute(&buf, &ctx); err != nil {
		return fmt.Errorf("can't generate types: %s", err)
	}

	return internal.WriteFormatted(buf.Bytes(), args.out)
}

func tag(str string) string {
	return "`ebpf:\"" + str + "\"`"
}
