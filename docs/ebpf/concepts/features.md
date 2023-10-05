# Feature Detection

Feature detection allows applications to check which eBPF-related features are
supported by the Linux kernel. This is useful for software that wants to be
compatible with multiple kernel versions and lets developers tailor their code
to use different eBPF features depending on what is supported by the running
kernel.

## Usage

In the `features` package, API calls follow a consistent pattern. The returned
errors mean the following:

- `nil` means the feature is supported.
- {{ godoc('ErrNotSupported') }} means the feature is not supported.
- Any other error suggests inconclusive detection, which could include false
  negatives.

For example, here's using {{ godoc('features/HaveProgramType') }}:

{{ go_example('DocDetectXDP', title="Detect kernel support for XDP programs") }}

!!! note ""
    Feature detection results are cached to minimize overhead, except for
    inconclusive results. Subsequent calls to a conclusive probe will
    consistently return the same result without rerunning the probe logic.

## Limitations

### {{ godoc ('features/HaveProgramHelper') }}

1. Not all combinations of program types and helpers can be probed. Conclusively
   probing a BPF helper means successfully loading a generated BPF program.
   Certain program types like `LSM`, `StructOps` and `Tracing` are difficult to
   generate on-the-fly, as they depend on other components or symbols being
   present in the kernel, making the probes fragile. Instead, for these types,
   we don't rely on successfully loading a program, but we look for specific
   kernel error responses instead, such as `ENOTSUPP`. This indicates the
   program type is known, but our generated program  was invalid (which is
   fine!).

2. This function only confirms the presence of the given BPF helper in the
   kernel. In cases where helpers themselves gain extra features in subsequent
   kernel releases, you'll have to write your own feature probe to test the
   particular combination of helper inputs you're looking for. Feel free to look
   at the implementation of package `features` for inspiration.

## Compared to `bpftool`

Linux's command-line utility `bpftool` offers the `bpftool feature probe`
subcommand for feature detection, inspiring the `features` package in {{ proj }}.
That subcommand provides an extensive overview of eBPF-related features,
issuing thousands of feature probes to identify kernel configuration options,
and detect map types, program types, and helper functions. {{ proj }} aims to
provide an equivalent set of feature probes, implemented in pure Go, to avoid a
`bpftool` runtime dependency, and to allow users to probe only the exact
features they need.
