package ebpf

import (
	"testing"
)

func TestMapABI(t *testing.T) {
	mabi := &MapABI{
		Type:       ArrayOfMaps,
		KeySize:    4,
		ValueSize:  2,
		MaxEntries: 3,
		InnerMap: &MapABI{
			Type: Array,
		},
	}

	if err := mabi.Check(abiFixtureMap()); err != nil {
		t.Error("ABI check found error:", err)
	}

	fm := abiFixtureMap()
	fm.abi.Type = Hash
	if err := mabi.Check(fm); err == nil {
		t.Error("Did not detect incorrect type")
	}

	fm = abiFixtureMap()
	fm.abi.KeySize = 3
	if err := mabi.Check(fm); err == nil {
		t.Error("Did not detect incorrect key size")
	}

	fm = abiFixtureMap()
	fm.abi.ValueSize = 23
	if err := mabi.Check(fm); err == nil {
		t.Error("Did not detect incorrect value size")
	}

	fm = abiFixtureMap()
	fm.abi.MaxEntries = 23
	if err := mabi.Check(fm); err == nil {
		t.Error("Did not detect incorrect max entries")
	}

	fm = abiFixtureMap()
	mabi.InnerMap.Type = Hash
	if err := mabi.Check(fm); err == nil {
		t.Error("Did not detect incorrect inner map type")
	}

	fm = abiFixtureMap()
	mabi.InnerMap = nil
	if err := mabi.Check(fm); err == nil {
		t.Error("Did not detect missing inner map ABI")
	}
}

func TestProgramABI(t *testing.T) {
	fabi := &ProgramABI{Type: SocketFilter}

	if err := fabi.Check(abiFixtureProgram()); err != nil {
		t.Error("ABI check found error:", err)
	}

	fp := abiFixtureProgram()
	fp.abi.Type = TracePoint
	if err := fabi.Check(fp); err == nil {
		t.Error("Did not detect incorrect type")
	}
}

func abiFixtureMapSpec() *MapSpec {
	return &MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		ValueSize:  2,
		MaxEntries: 3,
		InnerMap: &MapSpec{
			Type:    Array,
			KeySize: 2,
		},
	}
}

func abiFixtureMap() *Map {
	return &Map{
		abi: *newMapABIFromSpec(abiFixtureMapSpec()),
	}
}

func abiFixtureProgramSpec() *ProgramSpec {
	return &ProgramSpec{
		Type: SocketFilter,
	}
}

func abiFixtureProgram() *Program {
	return &Program{
		abi: *newProgramABIFromSpec(abiFixtureProgramSpec()),
	}
}
