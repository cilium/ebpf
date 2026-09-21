package internal

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestVerifierErrorWhitespace(t *testing.T) {
	b := []byte("unreachable insn 28")
	b = append(
		b,
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
	qt.Assert(t, qt.Not(qt.StringContains(errno524.Error(), "processed 39 insns")))

	// Include the previous line if the current one starts with a tab.
	invalidMember := readErrorFromFile(t, "testdata/invalid-member.log")
	qt.Assert(t, qt.StringContains(invalidMember.Error(), "STRUCT task_struct size=7744 vlen=218: cpus_mask type_id=109 bitfield_size=0 bits_offset=7744 Invalid member"))

	// Only include the last line.
	issue43 := readErrorFromFile(t, "testdata/issue-43.log")
	qt.Assert(t, qt.StringContains(issue43.Error(), "[11] FUNC helper_func2 type_id=10 vlen != 0"))
	qt.Assert(t, qt.Not(qt.StringContains(issue43.Error(), "[10] FUNC_PROTO (anon) return=3 args=(3 arg)")))

	// Include instruction that caused invalid register access.
	invalidR0 := readErrorFromFile(t, "testdata/invalid-R0.log")
	qt.Assert(t, qt.StringContains(invalidR0.Error(), "0: (95) exit: R0 !read_ok"))

	// Include symbol that doesn't match context type.
	invalidCtx := readErrorFromFile(t, "testdata/invalid-ctx-access.log")
	qt.Assert(t, qt.StringContains(invalidCtx.Error(), "func '__x64_sys_recvfrom' arg0 type FWD is not a struct: invalid bpf_context access off=0 size=8"))
}

func TestVerifierLogWithoutDiagnostics(t *testing.T) {
	for _, log := range [][]string{
		nil,
		{"0: (95) exit", "R0 !read_ok"},
	} {
		qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log))
	}

	log := []string{"Verification failed: earlier", "R0 !read_ok", "", " \t", "Verification failed: latest", "Reason:"}
	qt.Assert(t, qt.Equals(len(VerifierLogWithoutDiagnostics(log)), 0))
	qt.Assert(t, qt.Equals(len(log), 6))

	log = []string{"Verification failed: error"}
	qt.Assert(t, qt.Equals(len(VerifierLogWithoutDiagnostics(log)), 0))

	log = make([]string, 4096)
	log[0] = "R0 !read_ok"
	log[1] = "Verification failed: long diagnostics"
	log[len(log)-1] = "Suggestion:"
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log[:1]))

	log[0], log[1] = log[1], ""
	qt.Assert(t, qt.Equals(len(VerifierLogWithoutDiagnostics(log)), 0))

	log[0] = ""
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log))

	log = make([]string, 4096)
	log[len(log)-1] = "Verification failed: after blank lines"
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log[:len(log)-2]))
}

func TestVerifierLogMultipleDiagnostics(t *testing.T) {
	log := []string{
		"Unreleased reference id=1 alloc_insn=1",
		"",
		"Verification failed: Resource Lifetime Safety: Unreleased resource",
		"",
		"Reason:",
		"  Resource 1 was not released.",
		"",
		"Suggestion:",
		"  Release or transfer ownership",
		"  before exiting.",
		"",
		"Unreleased reference id=2 alloc_insn=2",
		"",
		"Verification failed: Resource Lifetime Safety: Unreleased resource",
		"",
		"Suggestion:",
		"  Release resource 2.",
		"",
		"processed 10 insns",
	}
	original := slices.Clone(log)
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log[:1]))
	qt.Assert(t, qt.DeepEquals(log, original))

	err := ErrorWithLog("test", errors.New("error"), []byte(strings.Join(log, "\n")))
	qt.Assert(t, qt.StringContains(err.Error(), "Unreleased reference id=1 alloc_insn=1"))
	qt.Assert(t, qt.Not(qt.StringContains(err.Error(), "Verification failed:")))
	qt.Assert(t, qt.StringContains(fmt.Sprintf("%+v", err), "Suggestion:\n\t  Release resource 2."))
	qt.Assert(t, qt.StringContains(fmt.Sprintf("%+v", err), "Unreleased reference id=2 alloc_insn=2"))
}

func TestVerifierLogDiagnosticsPrecheck(t *testing.T) {
	log := make([]string, 20)
	for i := range log {
		log[i] = "  diagnostic detail"
	}
	log[0] = "R0 !read_ok"
	log[1] = "Verification failed: error"
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log))

	log[9] = "Suggestion:"
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log))

	log[9], log[10] = "", "Suggestion:"
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log[:1]))

	log[1] = ""
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log))

	log[10] = "Verification failed: at precheck boundary"
	log[9] = "R0 !read_ok"
	qt.Assert(t, qt.DeepEquals(VerifierLogWithoutDiagnostics(log), log[:10]))
}

func readErrorFromFile(tb testing.TB, file string) *VerifierError {
	tb.Helper()

	contents, err := os.ReadFile(file)
	if err != nil {
		tb.Fatal("Read file:", err)
	}

	return ErrorWithLog("file", errors.New("error"), contents)
}
