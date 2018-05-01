package ebpf

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
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

// ProgramSpec defines a Program
type ProgramSpec struct {
	Type          ProgType
	Instructions  Instructions
	License       string
	KernelVersion uint32
	Refs          map[string][]*BPFInstruction
}

// RewriteMap rewrites a symbol to point at a Map.
func (ps *ProgramSpec) RewriteMap(symbol string, m Map) error {
	insns := ps.Refs[symbol]
	if len(insns) == 0 {
		return fmt.Errorf("unknown symbol %v", symbol)
	}
	for _, ins := range insns {
		if ins.OpCode != LdDW {
			return fmt.Errorf("symbol %v: not a valid map symbol, expected LdDW instruction", symbol)
		}
		ins.SrcRegister = 1
		ins.Constant = int32(m)
	}
	return nil
}

// RewriteUint64 rewrites a symbol to a 64bit constant.
func (ps *ProgramSpec) RewriteUint64(symbol string, value uint64) error {
	insns := ps.Refs[symbol]
	if len(insns) == 0 {
		return fmt.Errorf("unknown symbol %v", symbol)
	}
	for _, ins := range insns {
		if ins.OpCode != LdDW {
			return fmt.Errorf("symbol %v: expected LdDw instruction", symbol)
		}
		ins.Constant = int32(value & 0xffffffff)
		ins.extra.Constant = int32(value >> 32)
	}
	return nil
}

// Program represents a Program file descriptor
type Program int

// NewProgram creates a new Program
func NewProgram(spec *ProgramSpec) (Program, error) {
	if len(spec.Instructions) == 0 {
		return -1, fmt.Errorf("instructions cannot be empty")
	}
	var cInstructions []bpfInstruction
	for _, ins := range spec.Instructions {
		inss := ins.getCStructs()
		for _, ins2 := range inss {
			cInstructions = append(cInstructions, ins2)
		}
	}
	insCount := uint32(len(cInstructions))
	lic := []byte(spec.License)
	logs := make([]byte, LogBufSize)
	attr := progCreateAttr{
		progType:     spec.Type,
		insCount:     insCount,
		instructions: newPtr(unsafe.Pointer(&cInstructions[0])),
		license:      newPtr(unsafe.Pointer(&lic[0])),
		logLevel:     1,
		logSize:      LogBufSize,
		logBuf:       newPtr(unsafe.Pointer(&logs[0])),
	}
	fd, e := bpfCall(_ProgLoad, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	if e != 0 {
		if logs[0] != 0 {
			return -1, fmt.Errorf("%s:\n\t%s", bpfErrNo(e), strings.Replace(string(logs), "\n", "\n\t", -1))
		}
		return -1, bpfErrNo(e)
	}
	return Program(fd), nil
}

// GetFd gets the file descriptor value of the Program
func (bpf Program) GetFd() int {
	return int(bpf)
}

// Pin persists the Program past the lifetime of the process that created it
func (bpf Program) Pin(fileName string) error {
	return pinObject(fileName, uint32(bpf))
}

// Close unloads the program from the kernel.
func (bpf Program) Close() error {
	return syscall.Close(int(bpf))
}

// Test runs the Program in the kernel with the given input and returns the
// value returned by the eBPF program. outLen may be zero.
//
// Note: the kernel expects at least 14 bytes input for an ethernet header for
// XDP and SKB programs.
//
// This function requires at least Linux 4.12.
func (bpf Program) Test(in []byte) (uint32, []byte, error) {
	ret, out, _, err := bpf.testRun(in, 1)
	return ret, out, err
}

// Benchmark runs the Program with the given input for a number of times
// and returns the total time taken.
//
// This function requires at least Linux 4.12.
func (bpf Program) Benchmark(in []byte, repeat int) (time.Duration, error) {
	_, _, total, err := bpf.testRun(in, repeat)
	return total, err
}

var noProgTestRun bool
var detectProgTestRun sync.Once

func (bpf Program) testRun(in []byte, repeat int) (uint32, []byte, time.Duration, error) {
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
			fd:         uint32(prog),
			dataSizeIn: uint32(len(in)),
			dataIn:     newPtr(unsafe.Pointer(&in[0])),
		}
		_, errno := bpfCall(_ProgTestRun, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
		noProgTestRun = errno != 0
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
		fd:         uint32(bpf),
		dataSizeIn: uint32(len(in)),
		// NB: dataSizeOut is not read by the kernel
		dataIn:  newPtr(unsafe.Pointer(&in[0])),
		dataOut: newPtr(unsafe.Pointer(&out[0])),
		repeat:  uint32(repeat),
	}

	_, errno := bpfCall(_ProgTestRun, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	if errno != 0 {
		return 0, nil, 0, bpfErrNo(errno)
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

// LoadProgram loads a Program from a BPF file
func LoadProgram(fileName string) (Program, error) {
	ptr, err := getObject(fileName)
	return Program(ptr), err
}
