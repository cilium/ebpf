package ebpf

import (
	"bytes"
	"testing"
)

func TestProgramRun(t *testing.T) {
	pat := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := make([]byte, 14)

	// r1  : ctx_start
	// r1+4: ctx_end
	ins := Instructions{
		// r2 = *(r1+4)
		BPFIDstOffSrc(LdXW, Reg2, Reg1, 4),
		// r1 = *(r1+0)
		BPFIDstOffSrc(LdXW, Reg1, Reg1, 0),
		// r3 = r1
		BPFIDstSrc(MovSrc, Reg3, Reg1),
		// r3 += len(buf)
		BPFIDstImm(AddImm, Reg3, int32(len(buf))),
		// if r3 > r2 goto +len(pat)
		BPFIDstOffSrc(JGTSrc, Reg3, Reg2, int16(len(pat))),
	}
	for i, b := range pat {
		ins = append(ins, BPFIDstOffImm(StB, Reg1, int16(i), int32(b)))
	}
	ins = append(ins,
		// return 42
		BPFILdImm64(Reg0, 42),
		BPFIOp(Exit),
	)

	prog, err := NewProgram(XDP, ins, "MIT", 0)
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
