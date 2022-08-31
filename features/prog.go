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
	pc.helpers = make(map[ebpf.ProgramType]map[asm.BuiltinFunc]error)
	allocHelperCache()
}

func allocHelperCache() {
	for pt := ebpf.UnspecifiedProgram + 1; pt <= pt.Max(); pt++ {
		pc.helpers[pt] = make(map[asm.BuiltinFunc]error)
	}
}

var (
	pc progCache
)

type progCache struct {
	helperMu sync.Mutex
	helpers  map[ebpf.ProgramType]map[asm.BuiltinFunc]error
}

func createProgLoadAttr(pt ebpf.ProgramType, helper asm.BuiltinFunc) (*sys.ProgLoadAttr, error) {
	var expectedAttachType ebpf.AttachType
	var progFlags uint32

	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}

	if helper != asm.FnUnspec {
		insns = append(asm.Instructions{helper.Call()}, insns...)
	}

	buf := bytes.NewBuffer(make([]byte, 0, insns.Size()))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return nil, err
	}

	bytecode := buf.Bytes()
	instructions := sys.NewSlicePointer(bytecode)

	// Some programs have expected attach types which are checked during the
	// BPD_PROG_LOAD syscall.
	switch pt {
	case ebpf.CGroupSockAddr:
		expectedAttachType = ebpf.AttachCGroupInet4Connect
	case ebpf.CGroupSockopt:
		expectedAttachType = ebpf.AttachCGroupGetsockopt
	case ebpf.SkLookup:
		expectedAttachType = ebpf.AttachSkLookup
	case ebpf.Syscall:
		progFlags = unix.BPF_F_SLEEPABLE
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

	return &sys.ProgLoadAttr{
		ProgType:           sys.ProgType(pt),
		Insns:              instructions,
		InsnCnt:            uint32(len(bytecode) / asm.InstructionSize),
		ProgFlags:          progFlags,
		ExpectedAttachType: sys.AttachType(expectedAttachType),
		License:            sys.NewStringPointer("GPL"),
		KernVersion:        v.Kernel(),
	}, nil
}

// HaveProgType probes the running kernel for the availability of the specified program type.
//
// Deprecated: use HaveProgramType() instead.
var HaveProgType = HaveProgramType

// HaveProgramType probes the running kernel for the availability of the specified program type.
//
// See the package documentation for the meaning of the error return value.
func HaveProgramType(pt ebpf.ProgramType) (err error) {
	return haveProgramTypeMatrix.Result(pt)
}

func validateProgramType(pt ebpf.ProgramType) error {
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

func probeProgram(spec *ebpf.ProgramSpec) error {
	if spec.Instructions == nil {
		spec.Instructions = asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		}
	}
	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		prog.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported
	}

	return err
}

var haveProgramTypeMatrix = internal.FeatureMatrix[ebpf.ProgramType]{
	ebpf.SocketFilter:  {Version: "3.19"},
	ebpf.Kprobe:        {Version: "4.1"},
	ebpf.SchedCLS:      {Version: "4.1"},
	ebpf.SchedACT:      {Version: "4.1"},
	ebpf.TracePoint:    {Version: "4.7"},
	ebpf.XDP:           {Version: "4.8"},
	ebpf.PerfEvent:     {Version: "4.9"},
	ebpf.CGroupSKB:     {Version: "4.10"},
	ebpf.CGroupSock:    {Version: "4.10"},
	ebpf.LWTIn:         {Version: "4.10"},
	ebpf.LWTOut:        {Version: "4.10"},
	ebpf.LWTXmit:       {Version: "4.10"},
	ebpf.SockOps:       {Version: "4.13"},
	ebpf.SkSKB:         {Version: "4.14"},
	ebpf.CGroupDevice:  {Version: "4.15"},
	ebpf.SkMsg:         {Version: "4.17"},
	ebpf.RawTracepoint: {Version: "4.17"},
	ebpf.CGroupSockAddr: {
		Version: "4.17",
		Fn: func() error {
			return probeProgram(&ebpf.ProgramSpec{
				Type:       ebpf.CGroupSockAddr,
				AttachType: ebpf.AttachCGroupInet4Connect,
			})
		},
	},
	ebpf.LWTSeg6Local:          {Version: "4.18"},
	ebpf.LircMode2:             {Version: "4.18"},
	ebpf.SkReuseport:           {Version: "4.19"},
	ebpf.FlowDissector:         {Version: "4.20"},
	ebpf.CGroupSysctl:          {Version: "5.2"},
	ebpf.RawTracepointWritable: {Version: "5.2"},
	ebpf.CGroupSockopt: {
		Version: "5.3",
		Fn: func() error {
			return probeProgram(&ebpf.ProgramSpec{
				Type:       ebpf.CGroupSockopt,
				AttachType: ebpf.AttachCGroupGetsockopt,
			})
		},
	},
	// ebpf.Tracing:               {Version: "5.5"},
	ebpf.StructOps: {
		Version: "5.6",
		Fn: func() error {
			err := probeProgram(&ebpf.ProgramSpec{
				Type:    ebpf.StructOps,
				License: "GPL",
			})
			if errors.Is(err, sys.ENOTSUPP) {
				// ENOTSUPP means the program type is at least known to the kernel.
				return nil
			}
			return err
		},
	},
	// ebpf.Extension:             {Version: "5.6"},
	// ebpf.LSM:                   {Version: "5.7"},
	ebpf.SkLookup: {
		Version: "5.9",
		Fn: func() error {
			return probeProgram(&ebpf.ProgramSpec{
				Type:       ebpf.SkLookup,
				AttachType: ebpf.AttachSkLookup,
			})
		},
	},
	ebpf.Syscall: {
		Version: "5.14",
		Fn: func() error {
			return probeProgram(&ebpf.ProgramSpec{
				Type:  ebpf.Syscall,
				Flags: unix.BPF_F_SLEEPABLE,
			})
		},
	},
}

func init() {
	for key, ft := range haveProgramTypeMatrix {
		ft.Name = key.String()
		if ft.Fn == nil {
			key := key // avoid the dreaded loop variable problem
			ft.Fn = func() error { return probeProgram(&ebpf.ProgramSpec{Type: key}) }
		}
	}
}

// HaveProgramHelper probes the running kernel for the availability of the specified helper
// function to a specified program type.
// Return values have the following semantics:
//
//	err == nil: The feature is available.
//	errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//	err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned.
// Only `nil` and `ebpf.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveProgramHelper(pt ebpf.ProgramType, helper asm.BuiltinFunc) (err error) {
	defer func() {
		// This closure modifies a named return variable.
		err = wrapProbeErrors(err)
	}()

	if err := validateProgramType(pt); err != nil {
		return err
	}

	if err := validateProgramHelper(helper); err != nil {
		return err
	}

	return haveProgramHelper(pt, helper)
}

func validateProgramHelper(helper asm.BuiltinFunc) error {
	if helper > helper.Max() {
		return os.ErrInvalid
	}

	return nil
}

func haveProgramHelper(pt ebpf.ProgramType, helper asm.BuiltinFunc) error {
	pc.helperMu.Lock()
	defer pc.helperMu.Unlock()
	if err, ok := pc.helpers[pt][helper]; ok {
		return err
	}

	attr, err := createProgLoadAttr(pt, helper)
	if err != nil {
		return fmt.Errorf("couldn't create the program load attribute: %w", err)
	}

	fd, err := sys.ProgLoad(attr)
	if fd != nil {
		fd.Close()
	}

	switch {
	// EACCES occurs when attempting to create a program probe with a helper
	// while the register args when calling this helper aren't set up properly.
	// We interpret this as the helper being available, because the verifier
	// returns EINVAL if the helper is not supported by the running kernel.
	case errors.Is(err, unix.EACCES):
		// TODO: possibly we need to check verifier output here to be sure
		err = nil

	// EINVAL occurs when attempting to create a program with an unknown helper.
	// E2BIG occurs when BPFProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		// TODO: possibly we need to check verifier output here to be sure
		err = ebpf.ErrNotSupported
	}

	pc.helpers[pt][helper] = err

	return err
}

func progLoadProbeNotImplemented(pt ebpf.ProgramType) bool {
	switch pt {
	case ebpf.Tracing, ebpf.Extension, ebpf.LSM:
		return true
	}
	return false
}
