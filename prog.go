package ebpf

import (
	"fmt"
	"math"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
)

// Errors returned by the implementation
var (
	ErrNotSupported = errors.New("ebpf: not supported by kernel")
)

const (
	// Number of bytes to pad the output buffer for BPF_PROG_TEST_RUN.
	// This is currently the maximum of spare space allocated for SKB
	// and XDP programs, and equal to XDP_PACKET_HEADROOM + NET_IP_ALIGN.
	outputPad = 256 + 2
)

// DefaultVerifierLogSize is the default number of bytes allocated for the
// verifier log.
const DefaultVerifierLogSize = 64 * 1024

// ProgramSpec defines a Program
type ProgramSpec struct {
	Type          ProgType
	Instructions  Instructions
	License       string
	KernelVersion uint32
}

// Program represents a Program file descriptor
type Program struct {
	fd       uint32
	progType ProgType
}

// NewProgram creates a new Program.
func NewProgram(spec *ProgramSpec) (*Program, error) {
	if len(spec.Instructions) == 0 {
		return nil, fmt.Errorf("instructions cannot be empty")
	}
	bytecode, err := spec.Instructions.MarshalBinary()
	if err != nil {
		return nil, err
	}

	insCount := uint32(len(bytecode) / InstructionSize)
	lic := []byte(spec.License)
	attr := progCreateAttr{
		progType:     spec.Type,
		insCount:     insCount,
		instructions: newPtr(unsafe.Pointer(&bytecode[0])),
		license:      newPtr(unsafe.Pointer(&lic[0])),
	}

	fd, err := bpfCall(_ProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err == nil {
		prog := &Program{
			uint32(fd),
			spec.Type,
		}
		return prog, nil
	}

	// Something went wrong, re-run with the verifier enabled.
	logs := make([]byte, DefaultVerifierLogSize)
	attr.logLevel = 1
	attr.logSize = uint32(len(logs))
	attr.logBuf = newPtr(unsafe.Pointer(&logs[0]))

	_, nerr := bpfCall(_ProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if errors.Cause(nerr) == syscall.ENOSPC {
		return nil, errors.Wrap(err, "no debug since LogSize too small")
	}
	return nil, &loadError{nerr, string(logs)}
}

func (bpf *Program) String() string {
	return fmt.Sprintf("%s(%d)", bpf.progType, bpf.fd)
}

// FD gets the file descriptor value of the Program
func (bpf *Program) FD() int {
	return int(bpf.fd)
}

// Pin persists the Program past the lifetime of the process that created it
//
// This requires bpffs to be mounted above fileName. See http://cilium.readthedocs.io/en/doc-1.0/kubernetes/install/#mounting-the-bpf-fs-optional
func (bpf *Program) Pin(fileName string) error {
	return pinObject(fileName, bpf.fd)
}

// Close unloads the program from the kernel.
func (bpf *Program) Close() error {
	return syscall.Close(int(bpf.fd))
}

// Test runs the Program in the kernel with the given input and returns the
// value returned by the eBPF program. outLen may be zero.
//
// Note: the kernel expects at least 14 bytes input for an ethernet header for
// XDP and SKB programs.
//
// This function requires at least Linux 4.12.
func (bpf *Program) Test(in []byte) (uint32, []byte, error) {
	ret, out, _, err := bpf.testRun(in, 1)
	return ret, out, err
}

// Benchmark runs the Program with the given input for a number of times
// and returns the time taken per iteration.
//
// The returned value is the return value of the last execution of
// the program.
//
// This function requires at least Linux 4.12.
func (bpf *Program) Benchmark(in []byte, repeat int) (uint32, time.Duration, error) {
	ret, _, total, err := bpf.testRun(in, repeat)
	return ret, total, err
}

var noProgTestRun bool
var detectProgTestRun sync.Once

func (bpf *Program) testRun(in []byte, repeat int) (uint32, []byte, time.Duration, error) {
	if uint(repeat) > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("repeat is too high")
	}

	if len(in) == 0 {
		return 0, nil, 0, fmt.Errorf("missing input")
	}

	if uint(len(in)) > math.MaxUint32 {
		return 0, nil, 0, fmt.Errorf("input is too long")
	}

	detectProgTestRun.Do(func() {
		prog, err := NewProgram(&ProgramSpec{
			Type: XDP,
			Instructions: Instructions{
				BPFILdImm64(Reg0, 0),
				BPFIOp(Exit),
			},
			License: "MIT",
		})
		if err != nil {
			// This may be because we lack sufficient permissions, etc.
			return
		}
		defer prog.Close()

		// XDP progs require at least 14 bytes input
		in := make([]byte, 14)
		attr := progTestRunAttr{
			fd:         prog.fd,
			dataSizeIn: uint32(len(in)),
			dataIn:     newPtr(unsafe.Pointer(&in[0])),
		}
		_, err = bpfCall(_ProgTestRun, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		noProgTestRun = err != nil
	})

	if noProgTestRun {
		return 0, nil, 0, ErrNotSupported
	}

	// There is currently no way to tell the kernel about the size of the output buffer.
	// Combined with things like bpf_xdp_adjust_head() we don't really know what the final
	// size will be. Hence we allocate an output buffer which we hope will always be large
	// enough, and panic if the kernel wrote past the end of the allocation.
	// See https://marc.info/?l=linux-netdev&m=152283265832434&w=2
	out := make([]byte, len(in)+outputPad)

	attr := progTestRunAttr{
		fd:         bpf.fd,
		dataSizeIn: uint32(len(in)),
		// NB: dataSizeOut is not read by the kernel
		dataIn:  newPtr(unsafe.Pointer(&in[0])),
		dataOut: newPtr(unsafe.Pointer(&out[0])),
		repeat:  uint32(repeat),
	}

	_, err := bpfCall(_ProgTestRun, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return 0, nil, 0, err
	}

	if int(attr.dataSizeOut) > cap(out) {
		// Houston, we have a problem. The program created more data than we allocated,
		// and the kernel wrote past the end of our buffer.
		panic("kernel wrote past end of output buffer")
	}
	out = out[:int(attr.dataSizeOut)]

	total := time.Duration(attr.duration) * time.Nanosecond
	return attr.retval, out, total, nil
}

// LoadPinnedProgram loads a Program from a BPF file.
//
// Requires at least Linux 4.13, use LoadPinnedProgramExplicit on
// earlier versions.
func LoadPinnedProgram(fileName string) (*Program, error) {
	fd, err := getObject(fileName)
	if err != nil {
		return nil, err
	}
	var info progInfo
	err = getObjectInfoByFD(uint32(fd), unsafe.Pointer(&info), unsafe.Sizeof(info))
	if err != nil {
		return nil, fmt.Errorf("ebpf: can't retrieve program info: %s", err.Error())
	}
	return &Program{
		uint32(fd),
		ProgType(info.progType),
	}, nil
}

// LoadPinnedProgramExplicit loads a program with explicit parameters.
func LoadPinnedProgramExplicit(fileName string, typ ProgType) (*Program, error) {
	fd, err := getObject(fileName)
	if err != nil {
		return nil, err
	}
	return &Program{
		uint32(fd),
		typ,
	}, nil
}

type loadError struct {
	cause       error
	verifierLog string
}

func (le *loadError) Error() string {
	return fmt.Sprintf("%s: %s", le.cause, le.verifierLog)
}

func (le *loadError) Cause() error {
	return le.cause
}
