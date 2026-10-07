package internal

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
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

	err := ErrorWithLog("frob", errors.New("test"), b)
	qt.Assert(t, qt.Equals(err.Error(), "frob: test: unreachable insn 28"))

	for _, log := range [][]byte{
		nil,
		[]byte("\x00"),
		[]byte(" "),
	} {
		err = ErrorWithLog("frob", errors.New("test"), log)
		qt.Assert(t, qt.Equals(err.Error(), "frob: test"), qt.Commentf("empty log %q has incorrect format", log))
	}
}

func TestVerifierErrorWrapping(t *testing.T) {
	sentinel := errors.New("bad")

	ve := ErrorWithLog("frob", sentinel, nil)
	qt.Assert(t, qt.ErrorIs(ve, sentinel), qt.Commentf("should wrap provided error"))

	ve = ErrorWithLog("frob", sentinel, []byte("foo"))
	qt.Assert(t, qt.ErrorIs(ve, sentinel), qt.Commentf("should wrap provided error"))
	qt.Assert(t, qt.StringContains(ve.Error(), "foo"), qt.Commentf("verifier log should appear in error string"))
}

func TestVerifierErrorSummary(t *testing.T) {
	// Suppress the last line containing 'processed ... insns'.
	errno524 := readErrorFromFile(t, "testdata/errno524.log")
	qt.Assert(t, qt.StringContains(errno524.Error(), "JIT doesn't support bpf-to-bpf calls"))
	qt.Assert(t, qt.Not(qt.StringContains(errno524.Error(), "processed")))

	// Include the last two lines joined by a colon.
	invalidMember := readErrorFromFile(t, "testdata/invalid-member.log")
	qt.Assert(t, qt.StringContains(invalidMember.Error(), "STRUCT task_struct size=7744 vlen=218: cpus_mask type_id=109 bitfield_size=0 bits_offset=7744 Invalid member"))

	// Only include the last two lines.
	issue43 := readErrorFromFile(t, "testdata/issue-43.log")
	qt.Assert(t, qt.StringContains(issue43.Error(), "[11] FUNC helper_func2 type_id=10 vlen != 0"))
	qt.Assert(t, qt.Not(qt.StringContains(issue43.Error(), "[9] VAR btf_map type_id=1 linkage=1")))

	// Include instruction that caused invalid register access. Omit the
	// 'processed' line.
	invalidR0 := readErrorFromFile(t, "testdata/invalid-R0.log")
	qt.Assert(t, qt.StringContains(invalidR0.Error(), "0: (95) exit: R0 !read_ok (1 line omitted)"))
	qt.Assert(t, qt.Not(qt.StringContains(invalidR0.Error(), "processed")))

	// Include symbol that doesn't match context type.
	invalidCtx := readErrorFromFile(t, "testdata/invalid-ctx-access.log")
	qt.Assert(t, qt.StringContains(invalidCtx.Error(), "func '__x64_sys_recvfrom' arg0 type FWD is not a struct: invalid bpf_context access off=0 size=8"))

	// Error summary of a legacy log should contain the last 2 lines of the
	// verifier's instruction log.
	legacy := readErrorFromFile(t, "testdata/legacy.log")
	qt.Assert(t, qt.StringContains(legacy.Error(), "0: (95) exit: R0 !read_ok (1 line omitted)"))
	qt.Assert(t, qt.Not(qt.StringContains(legacy.Error(), "processed")))

	// Error summary of a log with diagnostics should be of the format "<Reason>
	// (<Suggestion>)", with trailing periods stripped.
	diag := readErrorFromFile(t, "testdata/diagnostics.log")
	qt.Assert(t, qt.StringContains(diag.Error(), "R0 has never been initialized on this path, so the verifier cannot use it as an input (Initialize R0 on every path before this instruction)"))
	qt.Assert(t, qt.Not(qt.StringContains(diag.Error(), "R0 !read_ok")))
	qt.Assert(t, qt.Not(qt.StringContains(diag.Error(), "processed")))
}

func TestVerifierErrorFormatting(t *testing.T) {
	legacy := readErrorFromFile(t, "testdata/legacy.log")

	qt.Assert(t, qt.Equals(fmt.Sprintf("%+-v", legacy), "%!v(BADFLAG)"))
	qt.Assert(t, qt.Equals(fmt.Sprintf("%1v", legacy), "%!v(BADWIDTH)"))
	qt.Assert(t, qt.Equals(fmt.Sprintf("%x", legacy), "%!x(BADVERB)"))

	// Legacy s and v without verb.
	testFormat(t, "%s", legacy, "file: error: 0: (95) exit: R0 !read_ok (1 line omitted)")
	testFormat(t, "%v", legacy, "file: error: 0: (95) exit: R0 !read_ok (1 line omitted)")

	// Legacy v without width specifier.
	testFormat(t, "%+v", legacy, `file: error:
	0: R1=ctx() R10=fp0
	0: (95) exit
	R0 !read_ok

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	// Legacy v with positive width specifier, omitting 2 lines.
	testFormat(t, "%+1v", legacy, `file: error:
	0: R1=ctx() R10=fp0
	(2 lines omitted)

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	// Legacy v with negative width specifier, omitting 2 lines.
	testFormat(t, "%-1v", legacy, `file: error:
	(2 lines omitted)
	R0 !read_ok

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	diag := readErrorFromFile(t, "testdata/diagnostics.log")

	// Diagnostics s and v without verb.
	summ := "file: error: R0 has never been initialized on this path, so the verifier cannot use it as an input (Initialize R0 on every path before this instruction)"
	testFormat(t, "%s", diag, summ)
	testFormat(t, "%v", diag, summ)

	// Diagnostics v without width specifier.
	testFormat(t, "%+v", diag, `file: error:
	0: R1=ctx() R10=fp0
	0: (95) exit
	R0 !read_ok

	Verification failed: Register Type Safety: Unreadable register

	Reason:
	  R0 has never been initialized on this path, so the verifier cannot use it as an input.

	At:
	  insn 0
	        | ^-- error: R0 is not readable
	  Instruction context:
	  >>> 0 | (95) exit

	Causal path:
	  no retained diagnostic events on this path

	Suggestion:
	  Initialize R0 on every path before this instruction.

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	// Diagnostics v with positive width specifier, omitting 2 lines.
	testFormat(t, "%+1v", diag, `file: error:
	0: R1=ctx() R10=fp0
	(2 lines omitted)

	Verification failed: Register Type Safety: Unreadable register

	Reason:
	  R0 has never been initialized on this path, so the verifier cannot use it as an input.

	At:
	  insn 0
	        | ^-- error: R0 is not readable
	  Instruction context:
	  >>> 0 | (95) exit

	Causal path:
	  no retained diagnostic events on this path

	Suggestion:
	  Initialize R0 on every path before this instruction.

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

	// Diagnostics v with negative width specifier, omitting 2 lines.
	testFormat(t, "%-1v", diag, `file: error:
	(2 lines omitted)
	R0 !read_ok

	Verification failed: Register Type Safety: Unreadable register

	Reason:
	  R0 has never been initialized on this path, so the verifier cannot use it as an input.

	At:
	  insn 0
	        | ^-- error: R0 is not readable
	  Instruction context:
	  >>> 0 | (95) exit

	Causal path:
	  no retained diagnostic events on this path

	Suggestion:
	  Initialize R0 on every path before this instruction.

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0`)

}

func TestVerifierErrorDiagnostics(t *testing.T) {
	ve := ErrorWithLog("error", errors.New("error"), []byte(`Verification failed: An error occurred!

Reason:
  There's a reason.
  For every error.

Some unindented string in between.

Suggestion:
  Some suggestion
  the user should try.

  Some indented, ignored text.`))

	qt.Assert(t, qt.Equals(ve.diagSection("Reason:"), "There's a reason. For every error"))
	qt.Assert(t, qt.Equals(ve.diagSection("Suggestion:"), "Some suggestion the user should try"))
}

func testFormat(tb testing.TB, f string, ve *VerifierError, want string) {
	tb.Helper()
	qt.Assert(tb, qt.Equals(fmt.Sprintf(f, ve), want))
}

func readErrorFromFile(tb testing.TB, file string) *VerifierError {
	tb.Helper()

	contents, err := os.ReadFile(file)
	if err != nil {
		tb.Fatal("Read file:", err)
	}

	return ErrorWithLog("file", errors.New("error"), contents)
}
