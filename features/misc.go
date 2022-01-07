package features

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	miscs.miscTypes = make(map[miscType]error, maxMiscType)
}

var (
	miscs miscCache
)

type miscCache struct {
	sync.Mutex
	miscTypes map[miscType]error
}

type miscType uint32

// Max returns the latest supported MiscType.
func (_ miscType) max() miscType {
	return maxMiscType - 1
}

const (
	// largeInsn support introduced in
	// commit c04c0d2b968ac45d6ef020316808ef6c82325a82
	largeInsn miscType = iota
	// boundedLoops support introduced in
	// commit 2589726d12a1b12eaaa93c7f1ea64287e383c7a5
	boundedLoops
	// v2ISA support introduced in
	// commit 92b31a9af73b3a3fc801899335d6c47966351830
	v2ISA
	// v3ISA support introduced in
	// commit 092ed0968bb648cd18e8a0430cd0a8a71727315c
	v3ISA
	// maxMiscType - Bound enum of FeatureTypes, has to be last in enum.
	maxMiscType
)

const (
	maxInsns = 4096
)

// HaveLargeInstructions probes the running kernel if more than 4096 instructions
// per program are supported.
// Return values have the following semantics:
//
//   err == nil: The feature is available.
//   errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//   err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned. Some program types cannot reliably be probed and
// will also return error. Only `nil` and `ebpf.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveLargeInstructions() error {
	return probeMisc(largeInsn)
}

// HaveBoundedLoops probes the running kernel if bounded loops are supported.
// Return values have the following semantics:
//
//   err == nil: The feature is available.
//   errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//   err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned. Some program types cannot reliably be probed and
// will also return error. Only `nil` and `ebpf.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveBoundedLoops() error {
	return probeMisc(boundedLoops)
}

// HaveV2ISA probes the running kernel if instructions of the v2 ISA are supported.
// Return values have the following semantics:
//
//   err == nil: The feature is available.
//   errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//   err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned. Some program types cannot reliably be probed and
// will also return error. Only `nil` and `ebpf.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveV2ISA() error {
	return probeMisc(v2ISA)
}

// HaveV3ISA probes the running kernel if instructions of the v3 ISA are supported.
// Return values have the following semantics:
//
//   err == nil: The feature is available.
//   errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//   err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned. Some program types cannot reliably be probed and
// will also return error. Only `nil` and `ebpf.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveV3ISA() error {
	return probeMisc(v3ISA)
}

// probeMisc checks the kernel for a given supported misc by creating
// a specialized program probe and loading it.
// Results are cached and persist throughout any process capability changes.
func probeMisc(mt miscType) error {
	if mt > mt.max() {
		return os.ErrInvalid
	}
	mc.Lock()
	defer mc.Unlock()
	err, ok := miscs.miscTypes[mt]
	if ok {
		return err
	}

	attr, err := createMiscProbeAttr(mt)
	if err != nil {
		return fmt.Errorf("couldn't create the attributes for the probe: %w", err)
	}

	fd, err := sys.ProgLoad(attr)

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given map type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported

	// EPERM is kept as-is and is not converted or wrapped.
	case errors.Is(err, unix.EPERM):
		break

	// Wrap unexpected errors.
	case err != nil:
		err = fmt.Errorf("unexpected error during feature probe: %w", err)

	default:
		fd.Close()
	}

	miscs.miscTypes[mt] = err

	return err
}

func createMiscProbeAttr(mt miscType) (*sys.ProgLoadAttr, error) {
	var (
		insns asm.Instructions
		label string
	)

	switch mt {
	case largeInsn:
		for i := 0; i < maxInsns; i++ {
			insns = append(insns, asm.Mov.Imm(asm.R0, 1))
		}
		insns = append(insns, asm.Return())
	case boundedLoops:
		label = "boundedLoop"
		insns = asm.Instructions{
			asm.Mov.Imm(asm.R0, 10),
			asm.Sub.Imm(asm.R0, 1).Sym(label),
			asm.JNE.Imm(asm.R0, 0, label),
			asm.Return(),
		}
	case v2ISA:
		label = "v2isa"
		insns = asm.Instructions{
			asm.Mov.Imm(asm.R0, 0).Sym(label),
			asm.JLT.Imm(asm.R0, 0, label),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		}
	case v3ISA:
		label = "v3isa"
		insns = asm.Instructions{
			asm.Mov.Imm(asm.R0, 0).Sym(label),
			asm.JLT.Imm32(asm.R0, 0, label),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		}
	default:
		return nil, fmt.Errorf("feature %d not yet implemented", mt)
	}

	if err := insns.RewriteJumps(); err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, insns.Size()))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return nil, err
	}

	bytecode := buf.Bytes()
	instructions := sys.NewSlicePointer(bytecode)

	return &sys.ProgLoadAttr{
		ProgType: sys.BPF_PROG_TYPE_SOCKET_FILTER,
		Insns:    instructions,
		InsnCnt:  uint32(len(bytecode) / asm.InstructionSize),
		License:  sys.NewStringPointer("MIT"),
	}, nil
}
