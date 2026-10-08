# Verifier Errors

Before a program is accepted by the kernel, it needs to pass the eBPF verifier.
If the program is rejected, the verifier emits a log describing why. This log
can range from a few lines to many megabytes, depending on the size and
complexity of the program. {{ proj }} parses this log and returns it as part of
a {{ godoc('VerifierError') }} from {{ godoc('NewProgram') }}, {{
godoc('NewCollection') }} and related APIs.

A VerifierError is typically wrapped in other errors by the time it's returned
to your application. By default (`%s`, `%v`, or calling `Error()`), the error
renders a single-line summary. On kernels with diagnostics support, this is a
short form of the 'Reason' and 'Suggestion' diagnostics.

```
load program: permission denied: R0 has never been initialized on this path, so
the verifier cannot use it as an input (Initialize R0 on every path before this
instruction)
```

On kernels before 7.3, it's the last two lines of the verifier log:

```
load program: permission denied: 0: (95) exit: R0 !read_ok (1 line omitted)
```

However, this amount of information is typically insufficient for properly
troubleshooting a verifier error. The default errors are kept short to avoid
overwhelming logging facilities when verifier errors are triggered repeatedly,
e.g. in a retry loop. To obtain more information, the error needs to be
explicitly expanded using string formatting. This allows the caller to choose
exactly which and how much of the log to display.

## Obtaining a {{ godoc('VerifierError') }}

Pull out the typed error to get access to its fields and formatting features:

```go
ve, _ := errors.AsType[*ebpf.VerifierError](err)

fmt.Printf("%-10v\n", ve)
```

!!! warning "Don't try formatting an `error`"

    Only use the typed (`ve`) VerifierError as an argument to `fmt`, never plain
    `err`! The `error` interface doesn't contain the `Format` method used by
    `fmt` to render its operands.

Formatting with `%-10v` renders the error header, the last 10 lines (if any) of
the instruction log, followed by diagnostics and the stats line:

```
load program: permission denied:
	0: R1=ctx() R10=fp0
	0: (95) exit
	R0 !read_ok

	Verification failed: Register Type Safety: Unreadable register
	...
    (more diagnostics)

	processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

We recommend writing this output to a file using {{ godoc('/fmt/Fprintf') }} so
it can be retrieved and inspected later.

## Formatting

The `%v` verb takes a `+`/`-` flag and an optional 'width' (`<n>`) to control
how many lines of the instruction log are displayed.

| Verb | Output |
| ---- | ------ |
| `%s`, `%v` | Single-line summary, see above. |
| `%+v`   | The full verifier log, followed by diagnostics and stats. |
| `%+<n>v` | The first `<n>` log lines, followed by diagnostics and stats. |
| `%-<n>v` | The last `<n>` log lines, followed by diagnostics and stats. |
| `%d`    | Only the diagnostics, if any. |

??? note "Invalid flag combinations"
    A width without a `+` or `-` flag (e.g. `%5v`) is invalid, as is combining
    both flags. Lines omitted are indicated by a `(<n> lines omitted)` marker.

### Examples

{{ go_example('DocVerifierError', title="Formatting a VerifierError in various ways") }}

## Diagnostics

{{ linux_version('7.3', "Kernels before 7.3 only emit the plain instruction
log, without a human-readable diagnostics report.") }}

Since Linux 7.3, the verifier appends a human-readable diagnostics report to
the log of every failed program load. It starts with a `Verification failed:`
line naming the error category, followed by several sections:

- `Reason:` explains why the verifier rejected the program.
- `At:` points at the source line and instruction that triggered the error.
- `Causal path:` lists the events that led up to the error, like branches
  taken and register assignments.
- `Suggestion:` describes a possible way to fix or work around the problem.

Diagnostics are always included when using `%+v` or `%-v`. To display only the
diagnostics, use the `%d` verb:

```
load program: permission denied:
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
```
