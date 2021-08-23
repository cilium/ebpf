// Code generated by bpf2go; DO NOT EDIT.

//go:build 386 || amd64 || amd64p32 || arm || arm64 || mipsle || mips64le || mips64p32le || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mipsle mips64le mips64p32le ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadExample returns the embedded CollectionSpec for example.
func loadExample() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ExampleBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load example: %w", err)
	}

	return spec, err
}

// loadExampleObjects loads example and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *exampleObjects
//     *examplePrograms
//     *exampleMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadExampleObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadExample()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// exampleSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type exampleSpecs struct {
	exampleProgramSpecs
	exampleMapSpecs
}

// exampleSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type exampleProgramSpecs struct {
	Filter *ebpf.ProgramSpec `ebpf:"filter"`
}

// exampleMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type exampleMapSpecs struct {
	Map1 *ebpf.MapSpec `ebpf:"map1"`
}

// exampleObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadExampleObjects or ebpf.CollectionSpec.LoadAndAssign.
type exampleObjects struct {
	examplePrograms
	exampleMaps
}

func (o *exampleObjects) Close() error {
	return _ExampleClose(
		&o.examplePrograms,
		&o.exampleMaps,
	)
}

// exampleMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadExampleObjects or ebpf.CollectionSpec.LoadAndAssign.
type exampleMaps struct {
	Map1 *ebpf.Map `ebpf:"map1"`
}

func (m *exampleMaps) Close() error {
	return _ExampleClose(
		m.Map1,
	)
}

// examplePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadExampleObjects or ebpf.CollectionSpec.LoadAndAssign.
type examplePrograms struct {
	Filter *ebpf.Program `ebpf:"filter"`
}

func (p *examplePrograms) Close() error {
	return _ExampleClose(
		p.Filter,
	)
}

func _ExampleClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed example_bpfel.o
var _ExampleBytes []byte
