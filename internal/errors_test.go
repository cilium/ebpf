package internal

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
	qt "github.com/frankban/quicktest"
)

func TestVerifierErrorWhitespace(t *testing.T) {
	b := []byte("unreachable insn 28")
	b = append(b,
		0xa,  // \n
		0xd,  // \r
		0x9,  // \t
		0x20, // space
		0, 0, // trailing NUL bytes
	)

	err := ErrorWithLog(errors.New("test"), b)
	qt.Assert(t, err.Error(), qt.Equals, "test: unreachable insn 28")

	err = ErrorWithLog(errors.New("test"), nil)
	qt.Assert(t, err.Error(), qt.Equals, "test")

	err = ErrorWithLog(errors.New("test"), []byte("\x00"))
	qt.Assert(t, err.Error(), qt.Equals, "test")

	err = ErrorWithLog(errors.New("test"), []byte(" "))
	qt.Assert(t, err.Error(), qt.Equals, "test")
}

func TestVerifierError(t *testing.T) {
	for _, test := range []struct {
		name string
		log  string
	}{
		{"missing null", "foo"},
		{"missing newline before null", "foo\x00"},
	} {
		t.Run("truncate "+test.name, func(t *testing.T) {
			ve := ErrorWithLog(syscall.ENOENT, []byte(test.log))
			qt.Assert(t, ve, qt.IsNotNil, qt.Commentf("should return error"))
			qt.Assert(t, ve.Truncated, qt.IsTrue, qt.Commentf("should be truncated"))
		})
	}

	ve := ErrorWithLog(syscall.ENOENT, nil)
	qt.Assert(t, ve, qt.IsNotNil, qt.Commentf("should return error without log or logErr"))

	errno524 := readErrorFromFile(t, "testdata/errno524.log")
	t.Log(errno524)
	qt.Assert(t, errno524.Error(), qt.Contains, "JIT doesn't support bpf-to-bpf calls")
	qt.Assert(t, errno524.Error(), qt.Not(qt.Contains), "processed 39 insns")

	invalidMember := readErrorFromFile(t, "testdata/invalid-member.log")
	t.Log(invalidMember)
	qt.Assert(t, invalidMember.Error(), qt.Contains, "STRUCT task_struct size=7744 vlen=218: cpus_mask type_id=109 bitfield_size=0 bits_offset=7744 Invalid member")

	issue43 := readErrorFromFile(t, "testdata/issue-43.log")
	t.Log(issue43)
	qt.Assert(t, issue43.Error(), qt.Contains, "[11] FUNC helper_func2 type_id=10 vlen != 0")
	qt.Assert(t, issue43.Error(), qt.Not(qt.Contains), "[10] FUNC_PROTO (anon) return=3 args=(3 arg)")

	truncated := readErrorFromFile(t, "testdata/truncated.log")
	t.Log(truncated)
	qt.Assert(t, truncated.Truncated, qt.IsTrue)
	qt.Assert(t, truncated.Error(), qt.Contains, "str_off: 3166088: str_len: 228")

	invalidR0 := readErrorFromFile(t, "testdata/invalid-R0.log")
	t.Log(invalidR0)
	qt.Assert(t, invalidR0.Error(), qt.Contains, "0: (95) exit: R0 !read_ok")

	invalidCtx := readErrorFromFile(t, "testdata/invalid-ctx-access.log")
	t.Log(invalidCtx)
	qt.Assert(t, invalidCtx.Error(), qt.Contains, "func '__x64_sys_recvfrom' arg0 type FWD is not a struct: invalid bpf_context access off=0 size=8")
}

func ExampleVerifierError() {
	err := &VerifierError{
		syscall.ENOSPC,
		[]string{"first", "second", "third"},
		false,
	}

	fmt.Printf("With %%s: %s\n", err)
	err.Truncated = true
	fmt.Printf("With %%v and a truncated log: %v\n", err)
	fmt.Printf("All log lines: %+v\n", err)
	fmt.Printf("First line: %+1v\n", err)
	fmt.Printf("Last two lines: %-2v\n", err)

	// Output: With %s: no space left on device: third (2 line(s) omitted)
	// With %v and a truncated log: no space left on device: second: third (truncated, 1 line(s) omitted)
	// All log lines: no space left on device:
	// 	first
	// 	second
	// 	third
	// 	(truncated)
	// First line: no space left on device:
	// 	first
	// 	(2 line(s) omitted)
	// 	(truncated)
	// Last two lines: no space left on device:
	// 	(1 line(s) omitted)
	// 	second
	// 	third
	// 	(truncated)
}

func readErrorFromFile(tb testing.TB, file string) *VerifierError {
	tb.Helper()

	contents, err := os.ReadFile(file)
	if err != nil {
		tb.Fatal("Read file:", err)
	}

	return ErrorWithLog(unix.EINVAL, contents)
}
