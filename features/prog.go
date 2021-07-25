package features

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
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

func createProgTypeAttr(pt ebpf.ProgramType) (*internal.BPFProgLoadAttr, error) {
	var expectedAttachType ebpf.AttachType

	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(insns)*asm.InstructionSize))
	err := insns.Marshal(buf, internal.NativeEndian)
	if err != nil {
		return nil, err
	}

	bytecode := buf.Bytes()
	instructions := internal.NewSlicePointer(bytecode)

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

	return nil
}

func haveProgType(pt ebpf.ProgramType) error {
	mc.Lock()
	defer mc.Unlock()
	err, ok := pc.progTypes[pt]
	if ok {
		return err
	}

	attr, err := createProgTypeAttr(pt)
	if err != nil {
		return fmt.Errorf("something went wrong: %w", err)
	}

	_, err = internal.BPFProgLoad(attr)

	switch {
	case err != nil:
		fmt.Println(err)
		err = ebpf.ErrNotSupported
	}
	pc.progTypes[pt] = err

	return err
}
