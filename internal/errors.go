package internal

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// ErrorWithLog wraps err in a VerifierError that includes the parsed verifier
// log buffer.
//
// The default error output is a summary of the full log. The latter can be
// accessed via VerifierError.Log or by formatting the error, see Format.
func ErrorWithLog(source string, err error, log []byte) *VerifierError {
	const whitespace = "\t\r\v\n "

	// Convert verifier log C string by truncating it on the first 0 byte
	// and trimming trailing whitespace before interpreting as a Go string.
	if i := bytes.IndexByte(log, 0); i != -1 {
		log = log[:i]
	}

	log = bytes.Trim(log, whitespace)
	if len(log) == 0 {
		return &VerifierError{source: source, Cause: err}
	}

	logLines := bytes.Split(log, []byte{'\n'})
	lines := make([]string, 0, len(logLines))
	for _, line := range logLines {
		// Don't remove leading white space on individual lines. We rely on it
		// when outputting logs.
		lines = append(lines, string(bytes.TrimRight(line, whitespace)))
	}

	ve := &VerifierError{source: source, Cause: err, Log: lines}
	ve.parse()

	return ve
}

// VerifierError includes information from the eBPF verifier log.
type VerifierError struct {
	// Call site identifier included before colon in wrapped errors.
	source string
	// The error which caused this error.
	Cause error
	// The instruction/verification log split into lines. Does not include
	// diagnostics (Verification failed: .., see [VerifierError.Diagnostics])
	// or stats (processed .., see [VerifierError.Stats]).
	Log []string
	// Human-readable diagnostics starting at 'Verification failed:', only
	// emitted since Linux 7.3. Empty on older kernels.
	Diagnostics []string
	// The trailing 'processed .. insns' summary line, if the log contained any.
	Stats string
}

func (le *VerifierError) Unwrap() error {
	return le.Cause
}

// Error returns the VerifierError as a string.
//
// If the verifier error contains human-friendly diagnostics introduced in Linux
// 7.3, only the 'Reason' and 'Suggestion' diagnostics are displayed in a short
// summary.
//
// On older kernels, returns the last 3 lines of the verifier (instruction) log.
func (le *VerifierError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", le.source, le.Cause.Error())

	if len(le.Log) == 0 && len(le.Diagnostics) == 0 {
		return b.String()
	}

	// Attempt to extract verifier diagnostics, falling back to displaying the
	// last 2 lines of the log if no diagnostics present.
	if le.Diagnostics != nil {
		reason := le.diagSection("Reason:")
		if reason == "" {
			reason = "no reason given"
		}

		suggestion := le.diagSection("Suggestion:")
		if suggestion == "" {
			suggestion = "no suggestion available"
		}

		b.WriteString(": ")
		b.WriteString(reason)
		b.WriteString(" (")
		b.WriteString(suggestion)
		b.WriteString(")")

		return b.String()
	}

	// No diagnostics, display just the last few lines of the instruction log,
	// joined by ': '.
	end := le.logEnd()
	for _, line := range end {
		b.WriteString(": ")
		b.WriteString(strings.TrimSpace(line))
	}

	b.WriteString(omitted(" ", len(le.Log)-len(end)))

	return b.String()
}

func omitted(prefix string, n int) string {
	if n == 1 {
		return prefix + "(1 line omitted)"
	} else if n > 1 {
		return fmt.Sprintf("%s(%d lines omitted)", prefix, n)
	}
	return ""
}

// parse splits the verifier log in Log into an instruction log, optional
// diagnostics and the trailing 'processed' summary line in a single scan. The
// resulting fields are subslices of the original log and non-overlapping.
//
// Since v7.3 ce7c9f6c599b ("Redesign Verification Log"), the verifier log
// contains a richer structure with human-readable reasons for verification
// failures.
//
// This is the structure of a verifier error with diagnostics info included:
//
//	0: R1=ctx() R10=fp0
//	0: (95) exit
//	R0 !read_ok
//
//	Verification failed: Register Type Safety: Unreadable register
//
//	Reason:
//	  R0 has never been initialized on this path, so the verifier cannot use it as an input.
//
//	At:
//	  insn 0
//	        | ^-- error: R0 is not readable
//	  Instruction context:
//	  >>> 0 | (95) exit
//
//	Causal path:
//	  no retained diagnostic events on this path
//
//	Suggestion:
//	  Initialize R0 on every path before this instruction.
//
//	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
func (le *VerifierError) parse() {
	log := le.Log

	// The full log lives in Log by default. Markers cut the current section
	// and move the remaining lines to the next bucket.
	cur, start := &le.Log, 0
	for i, line := range log {
		switch {
		case strings.HasPrefix(line, "Verification failed:"):
			// Roll over to diagnostics.
			start = i
			*cur = log[:i]
			cur = &le.Diagnostics
			le.Diagnostics = log[i:]
		case strings.HasPrefix(line, "processed "):
			// Stats are always one line.
			*cur = log[start:i]
			le.Stats = line
		}
	}

	le.Log = trimTrailingEmpty(le.Log)
	le.Diagnostics = trimTrailingEmpty(le.Diagnostics)
}

// trimTrailingEmpty returns lines with any trailing empty lines removed.
func trimTrailingEmpty(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	for lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// diagSection returns the contents of the diagnostics section with the given
// header, e.g. "Suggestion:". The diagSection body runs until the next empty or
// unindented line. Since bodies are sentences wrapped across indented lines,
// returns the lines joined by single spaces. Example:
//
//	Suggestion:
//	  Initialize R0 on every path
//	  before this instruction.
func (le *VerifierError) diagSection(header string) string {
	var b strings.Builder
	var found bool

	for _, l := range le.Diagnostics {
		if !found {
			if l == header {
				found = true
			}
			continue
		}

		// Read until the first empty or non-indented line.
		if l == "" || !strings.HasPrefix(l, " ") {
			break
		}

		// Join lines by space.
		if b.Len() > 0 {
			b.WriteByte(' ')
		}

		// Trim whitespace.
		b.WriteString(strings.TrimSpace(l))
	}

	// Trim trailing periods from the full string.
	return strings.TrimSuffix(b.String(), ".")
}

// logEnd returns the last two lines (if any) of the verified instruction log,
// for inclusion in error summaries.
func (le *VerifierError) logEnd() []string {
	l := len(le.Log)
	return le.Log[l-min(l, 2):]
}

// Format implements the VerifierError's string formatting features. Usage is
// documented on [VerifierError] itself.
func (le *VerifierError) Format(f fmt.State, verb rune) {
	switch verb {
	case 's':
		io.WriteString(f, le.Error())

	case 'v':
		n, haveWidth := f.Width()
		if haveWidth {
			n = min(len(le.Log), n)
		}
		if n == 0 {
			n = len(le.Log)
		}

		// Caller didn't specify any flags.
		if !f.Flag('+') && !f.Flag('-') {
			if haveWidth {
				// Width requires a (start or end) flag.
				io.WriteString(f, "%!v(BADWIDTH)")
				return
			}

			io.WriteString(f, le.Error())
			return
		}

		// Only one flag is allowed at a time.
		if f.Flag('+') && f.Flag('-') {
			io.WriteString(f, "%!v(BADFLAG)")
			return
		}

		fmt.Fprintf(f, "%s: %s:\n", le.source, le.Cause.Error())

		omit := len(le.Log) - n
		if f.Flag('-') {
			// Print 'omitted' followed by last n lines of log.
			if omit > 0 {
				io.WriteString(f, omitted("\t", omit))
				io.WriteString(f, "\n")
			}
			writeStrings(f, "\t", le.Log[omit:])
		} else {
			// Print first n (or all) lines of log followed by 'omitted'.
			writeStrings(f, "\t", le.Log[:n])
			if omit > 0 {
				io.WriteString(f, omitted("\n\t", omit))
			}
		}

		// Print diagnostics if present.
		if le.Diagnostics != nil {
			io.WriteString(f, "\n\n")
			writeStrings(f, "\t", le.Diagnostics)
		}

		// Print 'processed ..' line.
		io.WriteString(f, "\n\n\t")
		io.WriteString(f, le.Stats)

	default:
		fmt.Fprintf(f, "%%!%c(BADVERB)", verb)
	}
}

// writeStrings writes lines to w with an optional per-line prefix.
//
// Empty lines result in a newline being written to the writer, ignoring prefix.
// The final newline is omitted.
func writeStrings(w io.Writer, prefix string, lines []string) {
	for i, l := range lines {
		if prefix != "" && l != "" {
			io.WriteString(w, prefix)
		}
		io.WriteString(w, l)
		if i < len(lines)-1 {
			io.WriteString(w, "\n")
		}
	}
}
