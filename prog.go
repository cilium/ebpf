package ebpf

import (
	"fmt"
	"math"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ProgramSpec is an interface that can initialize a new Program
type ProgramSpec interface {
	ProgType() ProgType
	Instructions() *Instructions
	License() string
	KernelVersion() uint32
}

// Program represents a Program file descriptor
type Program int

// NewProgram creates a new Program
func NewProgram(progType ProgType, instructions *Instructions, license string, kernelVersion uint32) (Program, error) {
	if instructions == nil {
		return -1, fmt.Errorf("instructions cannot be nil")
	}
	var cInstructions []bpfInstruction
	for _, ins := range *instructions {
		inss := ins.getCStructs()
		for _, ins2 := range inss {
			cInstructions = append(cInstructions, ins2)
		}
	}
	insCount := uint32(len(cInstructions))
	if insCount > MaxBPFInstructions {
		return -1, fmt.Errorf("max instructions, %d, exceeded", MaxBPFInstructions)
	}
	lic := []byte(license)
	logs := make([]byte, LogBufSize)
	fd, e := bpfCall(_ProgLoad, unsafe.Pointer(&progCreateAttr{
		progType:     progType,
		insCount:     insCount,
		instructions: newPtr(unsafe.Pointer(&cInstructions[0])),
		license:      newPtr(unsafe.Pointer(&lic[0])),
		logLevel:     1,
		logSize:      LogBufSize,
		logBuf:       newPtr(unsafe.Pointer(&logs[0])),
	}), 48)
	if e != 0 {
		if logs[0] != 0 {
			return -1, fmt.Errorf("%s:\n\t%s", bpfErrNo(e), strings.Replace(string(logs), "\n", "\n\t", -1))
		}
		return -1, bpfErrNo(e)
	}
	return Program(fd), nil
}

// NewProgramFromSpec creates a new Program from the ProgramSpec interface
func NewProgramFromSpec(spec ProgramSpec) (Program, error) {
	return NewProgram(spec.ProgType(), spec.Instructions(), spec.License(), spec.KernelVersion())
}

// GetFd gets the file descriptor value of the Program
func (bpf Program) GetFd() int {
	return int(bpf)
}

// Pin persists the Program past the lifetime of the process that created it
func (bpf Program) Pin(fileName string) error {
	return pinObject(fileName, uint32(bpf))
}

// Test runs the Program in the kernel with the given input and returns the
// value returned by the eBPF program. outLen may be zero.
//
// Note: the kernel expects at least 14 bytes input for an ethernet header for
// XDP and SKB programs.
//
// This function requires at least Linux 4.12.
func (bpf Program) Test(in []byte, outLen int) (uint32, []byte, error) {
	ret, out, _, err := bpf.testRun(in, outLen, 1)
	return ret, out, err
}

// Benchmark runs the Program with the given input for a number of times
// and returns the total time taken.
//
// This function requires at least Linux 4.12.
func (bpf Program) Benchmark(in []byte, repeat int) (time.Duration, error) {
	_, _, total, err := bpf.testRun(in, 0, repeat)
	return total, err
}

func (bpf Program) testRun(in []byte, outLen int, repeat int) (uint32, []byte, time.Duration, error) {
	if repeat > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("repeat is too high")
	}

	if len(in) == 0 {
		return 0, nil, 0, fmt.Errorf("missing input")
	}

	if len(in) > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("input is too long")
	}

	if outLen > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("output is too long")
	}

	var out []byte
	var outPtr syscallPtr
	if outLen > 0 {
		out = make([]byte, outLen)
		outPtr = newPtr(unsafe.Pointer(&out[0]))
	}

	attr := progTestRunAttr{
		fd:          uint32(bpf),
		dataSizeIn:  uint32(len(in)),
		dataSizeOut: uint32(len(out)),
		dataIn:      newPtr(unsafe.Pointer(&in[0])),
		dataOut:     outPtr,
		repeat:      uint32(repeat),
	}

	_, errno := bpfCall(_ProgTestRun, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	if errno != 0 {
		if errno == syscall.EINVAL {
			// bpf() returns EINVAL if _ProgTestRun is not supported AND if
			// input size is out of bounds.
			return 0, nil, 0, fmt.Errorf("kernel too old or input too small: %v", errno)
		}
		return 0, nil, 0, bpfErrNo(errno)
	}

	if out != nil {
		out = out[:attr.dataSizeOut]
	}

	total := time.Duration(attr.duration) * time.Nanosecond
	return attr.retval, out, total, nil
}

// LoadProgram loads a Program from a BPF file
func LoadProgram(fileName string) (Program, error) {
	ptr, err := getObject(fileName)
	return Program(ptr), err
}
