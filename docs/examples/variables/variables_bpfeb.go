// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadVariables returns the embedded CollectionSpec for variables.
func loadVariables() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_VariablesBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load variables: %w", err)
	}

	return spec, err
}

// loadVariablesObjects loads variables and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*variablesObjects
//	*variablesPrograms
//	*variablesMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadVariablesObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadVariables()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// variablesSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type variablesSpecs struct {
	variablesProgramSpecs
	variablesMapSpecs
	variablesVariableSpecs
}

// variablesProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type variablesProgramSpecs struct {
	ConstExample  *ebpf.ProgramSpec `ebpf:"const_example"`
	GlobalExample *ebpf.ProgramSpec `ebpf:"global_example"`
	HiddenExample *ebpf.ProgramSpec `ebpf:"hidden_example"`
}

// variablesMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type variablesMapSpecs struct {
}

// variablesVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type variablesVariableSpecs struct {
	ConstU32  *ebpf.VariableSpec `ebpf:"const_u32"`
	GlobalU16 *ebpf.VariableSpec `ebpf:"global_u16"`
}

// variablesObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadVariablesObjects or ebpf.CollectionSpec.LoadAndAssign.
type variablesObjects struct {
	variablesPrograms
	variablesMaps
	variablesVariables
}

func (o *variablesObjects) Close() error {
	return _VariablesClose(
		&o.variablesPrograms,
		&o.variablesMaps,
	)
}

// variablesMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadVariablesObjects or ebpf.CollectionSpec.LoadAndAssign.
type variablesMaps struct {
}

func (m *variablesMaps) Close() error {
	return _VariablesClose()
}

// variablesVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadVariablesObjects or ebpf.CollectionSpec.LoadAndAssign.
type variablesVariables struct {
	ConstU32  *ebpf.Variable `ebpf:"const_u32"`
	GlobalU16 *ebpf.Variable `ebpf:"global_u16"`
}

// variablesPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadVariablesObjects or ebpf.CollectionSpec.LoadAndAssign.
type variablesPrograms struct {
	ConstExample  *ebpf.Program `ebpf:"const_example"`
	GlobalExample *ebpf.Program `ebpf:"global_example"`
	HiddenExample *ebpf.Program `ebpf:"hidden_example"`
}

func (p *variablesPrograms) Close() error {
	return _VariablesClose(
		p.ConstExample,
		p.GlobalExample,
		p.HiddenExample,
	)
}

func _VariablesClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed variables_bpfeb.o
var _VariablesBytes []byte
