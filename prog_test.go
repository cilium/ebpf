package ebpf

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/newtools/ebpf/asm"
)

func TestProgramRun(t *testing.T) {
	pat := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := make([]byte, 14)

	// r1  : ctx_start
	// r1+4: ctx_end
	ins := asm.Instructions{
		// r2 = *(r1+4)
		asm.LoadMem(asm.R2, asm.R1, 4, asm.Word),
		// r1 = *(r1+0)
		asm.LoadMem(asm.R1, asm.R1, 0, asm.Word),
		// r3 = r1
		asm.Mov.Reg(asm.R3, asm.R1),
		// r3 += len(buf)
		asm.Add.Imm(asm.R3, int32(len(buf))),
		// if r3 > r2 goto +len(pat)
		asm.JGT.Reg(asm.R3, asm.R2, "out"),
	}
	for i, b := range pat {
		ins = append(ins, asm.StoreImm(asm.R1, int16(i), int64(b), asm.Byte))
	}
	ins = append(ins,
		// return 42
		asm.LoadImm(asm.R0, 42, asm.DWord).Sym("out"),
		asm.Return(),
	)

	t.Log(ins)

	prog, err := NewProgram(&ProgramSpec{"test", XDP, ins, "MIT", 0})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	ret, out, err := prog.Test(buf)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 42 {
		t.Error("Expected return value to be 42, got", ret)
	}

	if !bytes.Equal(out[:len(pat)], pat) {
		t.Errorf("Expected %v, got %v", pat, out)
	}
}

func TestProgramPin(t *testing.T) {
	prog, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	tmp, err := ioutil.TempDir("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}
	prog.Close()

	prog, err = LoadPinnedProgram(path)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	if prog.abi.Type != SocketFilter {
		t.Error("Expected pinned program to have type SocketFilter, but got", prog.abi.Type)
	}
}

func TestProgramVerifierOutput(t *testing.T) {
	_, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.Return(),
		},
		License: "MIT",
	})
	if err == nil {
		t.Fatal("Expected program to be invalid")
	}

	if strings.Index(err.Error(), "exit") == -1 {
		t.Error("No verifier output in error message")
	}
}

func TestProgramName(t *testing.T) {
	prog, err := NewProgram(&ProgramSpec{
		Name: "test",
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	info, err := bpfGetProgInfoByFD(prog.fd)
	if err != nil {
		t.Fatal(err)
	}

	if name := convertCString(info.name[:]); name != "test" {
		t.Errorf("Name is not test, got '%s'", name)
	}

	for name, valid := range map[string]bool{
		"test":                         true,
		"":                             true,
		"a-b":                          false,
		"yeah so":                      false,
		"more_than_16_characters_long": false,
	} {
		err := checkName(name)
		if result := err == nil; result != valid {
			t.Errorf("Name '%s' classified incorrectly", name)
		}
	}
}
