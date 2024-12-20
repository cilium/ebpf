// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package test

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type testBar struct {
	A uint64
	B uint32
	_ [4]byte
}

type testBarfoo struct {
	Bar int64
	Baz bool
	_   [3]byte
	Boo testE
}

type testBaz struct{ A uint64 }

type testE uint32

const (
	testHOOPY  testE = 0
	testEHOOPY testE = 0
	testFROOD  testE = 1
	testEFROOD testE = 1
)

type testUbar struct {
	A uint32
	_ [4]byte
}

// loadTest returns the embedded CollectionSpec for test.
func loadTest() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TestBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load test: %w", err)
	}

	return spec, err
}

// loadTestObjects loads test and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*testObjects
//	*testPrograms
//	*testMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTestObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTest()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// testSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type testSpecs struct {
	testProgramSpecs
	testMapSpecs
	testVariableSpecs
}

// testProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type testProgramSpecs struct {
	Filter *ebpf.ProgramSpec `ebpf:"filter"`
}

// testMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type testMapSpecs struct {
	Map1 *ebpf.MapSpec `ebpf:"map1"`
}

// testVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type testVariableSpecs struct {
	AnInt       *ebpf.VariableSpec `ebpf:"an_int"`
	IntArray    *ebpf.VariableSpec `ebpf:"int_array"`
	MyConstant  *ebpf.VariableSpec `ebpf:"my_constant"`
	StructArray *ebpf.VariableSpec `ebpf:"struct_array"`
	StructConst *ebpf.VariableSpec `ebpf:"struct_const"`
	StructVar   *ebpf.VariableSpec `ebpf:"struct_var"`
	UnionVar    *ebpf.VariableSpec `ebpf:"union_var"`
}

// testObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type testObjects struct {
	testPrograms
	testMaps
	testVariables
}

func (o *testObjects) Close() error {
	return _TestClose(
		&o.testPrograms,
		&o.testMaps,
	)
}

// testMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type testMaps struct {
	Map1 *ebpf.Map `ebpf:"map1"`
}

func (m *testMaps) Close() error {
	return _TestClose(
		m.Map1,
	)
}

// testVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type testVariables struct {
	AnInt       *ebpf.Variable `ebpf:"an_int"`
	IntArray    *ebpf.Variable `ebpf:"int_array"`
	MyConstant  *ebpf.Variable `ebpf:"my_constant"`
	StructArray *ebpf.Variable `ebpf:"struct_array"`
	StructConst *ebpf.Variable `ebpf:"struct_const"`
	StructVar   *ebpf.Variable `ebpf:"struct_var"`
	UnionVar    *ebpf.Variable `ebpf:"union_var"`
}

// testPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type testPrograms struct {
	Filter *ebpf.Program `ebpf:"filter"`
}

func (p *testPrograms) Close() error {
	return _TestClose(
		p.Filter,
	)
}

func _TestClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed test_bpfel.o
var _TestBytes []byte
