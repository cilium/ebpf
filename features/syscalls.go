package features

import internalFeatures "github.com/cilium/ebpf/internal/features"

// HaveNestedMaps returns a nil error if nested maps are supported.
func HaveNestedMaps() error {
	return internalFeatures.HaveNestedMaps()
}

// HaveMapMutabilityModifiers returns a nil error if map
// mutability modifiers are supported.
func HaveMapMutabilityModifiers() error {
	return internalFeatures.HaveMapMutabilityModifiers()
}

// HaveMmapableMaps returns a nil error if mmapable maps
// are supported.
func HaveMmapableMaps() error {
	return internalFeatures.HaveMmapableMaps()
}

// HaveInnerMaps returns a nil error if inner maps are supported.
func HaveInnerMaps() error {
	return internalFeatures.HaveInnerMaps()
}

// HaveNoPreallocMaps returns a nil error if the flag for
// creating maps that are not pre-allocated is supported.
func HaveNoPreallocMaps() error {
	return internalFeatures.HaveNoPreallocMaps()
}

// HaveObjName returns a nil error if object names are supported
func HaveObjName() error {
	return internalFeatures.HaveObjName()
}

// ObjNameAllowsDot returns a nil error if object names support
// the dot character, i.e. ".".
func ObjNameAllowsDot() error {
	return internalFeatures.ObjNameAllowsDot()
}

// HaveBatchAPI returns a nil error if batch operations are supported
func HaveBatchAPI() error {
	return internalFeatures.HaveBatchAPI()
}

// HaveProbeReadKernel returns a nil error if kprobes are supported.
func HaveProbeReadKernel() error {
	return internalFeatures.HaveProbeReadKernel()
}

// HaveBPFToBPFCalls returns a nil error if bpf programs can call other bpf
// programs.
func HaveBPFToBPFCalls() error {
	return internalFeatures.HaveBPFToBPFCalls()
}

// HaveSyscallWrapper returns a nil error if syscall wrapper is not supported.
func HaveSyscallWrapper() error {
	return internalFeatures.HaveSyscallWrapper()
}

// HaveProgramExtInfos returns a nil error if program BTF is supported
func HaveProgramExtInfos() error {
	return internalFeatures.HaveProgramExtInfos()
}

// HaveProgramInfoMapIDs returns a nil error if retrieving map ids from
// program's object info is supported.
func HaveProgramInfoMapIDs() error {
	return internalFeatures.HaveProgramInfoMapIDs()
}

// HaveProgTestRun returns a nil error if the bpf command
// PROG_TEST_RUN is supported.
func HaveProgTestRun() error {
	return internalFeatures.HaveProgTestRun()
}
