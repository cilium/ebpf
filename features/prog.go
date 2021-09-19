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
	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	pc.progTypes = make(map[ebpf.ProgramType]error)
}

var (
	pc progCache
)

type progCache struct {
	sync.Mutex
	progTypes map[ebpf.ProgramType]error
}

func createProgLoadAttr(pt ebpf.ProgramType) (*internal.BPFProgLoadAttr, error) {
	var expectedAttachType ebpf.AttachType

	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(insns)*asm.InstructionSize))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return nil, err
	}

	bytecode := buf.Bytes()
	instructions := internal.NewSlicePointer(bytecode)

	// Some programs have expected attach types which are checked during the
	// BPD_PROG_LOAD syscall.
	switch pt {
	case ebpf.CGroupSockAddr:
		expectedAttachType = ebpf.AttachCGroupInet4Connect
	case ebpf.CGroupSockopt:
		expectedAttachType = ebpf.AttachCGroupGetsockopt
	case ebpf.SkLookup:
		expectedAttachType = ebpf.AttachSkLookup
	default:
		expectedAttachType = ebpf.AttachNone
	}

	// Kernels before 5.0 (6c4fc209fcf9 "bpf: remove useless version check for prog load")
	// require the version field to be set to the value of the KERNEL_VERSION
	// macro for kprobe-type programs.
	v, err := internal.KernelVersion()
	if err != nil {
		return nil, fmt.Errorf("detecting kernel version: %w", err)
	}
	kv := v.Kernel()

	return &internal.BPFProgLoadAttr{
		ProgType:           uint32(pt),
		Instructions:       instructions,
		InsCount:           uint32(len(bytecode) / asm.InstructionSize),
		ExpectedAttachType: uint32(expectedAttachType),
		License:            internal.NewStringPointer("GPL"),
		KernelVersion:      kv,
	}, nil
}

// HaveProgType probes the running kernel for the availability of the specified program type.
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
func HaveProgType(pt ebpf.ProgramType) error {
	if err := validateProgType(pt); err != nil {
		return err
	}

	return haveProgType(pt)

}

func validateProgType(pt ebpf.ProgramType) error {
	if pt > pt.Max() {
		return os.ErrInvalid
	}

	if progLoadProbeNotImplemented(pt) {
		// A probe for a these prog types has BTF requirements we currently cannot meet
		// Once we figure out how to add a working probe in this package, we can remove
		// this check
		return fmt.Errorf("a probe for ProgType %s isn't implemented", pt.String())
	}

	return nil
}

func haveProgType(pt ebpf.ProgramType) error {
	pc.Lock()
	defer pc.Unlock()
	err, ok := pc.progTypes[pt]
	if ok {
		return err
	}

	attr, err := createProgLoadAttr(pt)
	if err != nil {
		return fmt.Errorf("couldn't create the program load attribute: %w", err)
	}

	fd, err := internal.BPFProgLoad(attr)

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when BPFProgLoadAttr contains non-zero bytes past the end
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

	pc.progTypes[pt] = err

	return err
}

func progLoadProbeNotImplemented(pt ebpf.ProgramType) bool {
	switch pt {
	case ebpf.Tracing, ebpf.StructOps, ebpf.Extension, ebpf.LSM:
		return true
	}
	return false
}
