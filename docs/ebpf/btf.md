# BPF Type Format (BTF)

BPF Type Format (BTF) is a compact type metadata format used by the kernel and
eBPF toolchains. In {{ proj }}, BTF commonly appears in two places:

- in eBPF ELF objects produced by your build
- in the running kernel, typically via `/sys/kernel/btf/vmlinux`

BTF is useful for more than type introspection. Many eBPF features rely on it
to describe map layouts, global variables, attach targets, and CO-RE
relocations. Build eBPF objects with `clang -g` by default. BTF is a normal part
of modern eBPF workflows and supports features that many applications rely on.

## Use cases for BTF

BTF enhances many eBPF features, and is even required by some features:

- **ELF loading**: map definitions, global variables, and other metadata are
  encoded in BTF sections in ELF objects (when using `clang -g`).
- **CO-RE**: Compile Once, Run Everywhere relocations require object BTF and
  target kernel BTF to adapt memory accesses to the running kernel.
- **BTF-aware attach targets**: attach types such as `fentry`, `fexit`,
  `struct_ops`, and BTF tracepoints require BTF to identify kernel types and
  functions to attach to.
- **[kfuncs](kfuncs.md)**: the spiritual successors to BPF helpers; the
  verifier uses BTF information to identify which kfunc eBPF programs want to
  call.
- **Map type information**: BTF can describe key and value layouts for maps,
  making for nice pretty-printed output in `bpftool map dump`. Some map types,
  like Struct Ops, require BTF to work.
- **Debug metadata**: function and line information may be encoded using BTF
  and loaded with programs, so matching source code can be displayed alongside
  eBPF bytecode.

If you are building portable eBPF applications, BTF is a prerequisite for
CO-RE-based workflows and several BTF-aware program types. See [Portable
eBPF](guides/portable-ebpf.md) for background on cross-kernel compatibility.


!!! note ""
    When building eBPF C code with `clang -g`, use `llvm-strip -g` to remove
    DWARF debug sections, resulting in significantly smaller objects. These
    sections are not read by {{ proj }} and won't affect the behaviour of your
    program.

## Reading BTF from an ELF

If an eBPF ELF was built with `clang -g`, {{ proj }} will parse its BTF while
loading the object. The result is exposed as {{ godoc('CollectionSpec.Types') }}.

{{ go_example('DocBTFTypeByName', title='Inspect BTF types from an ELF object') }}

If the ELF was built without BTF, `CollectionSpec.Types` will be `nil`.

The returned `btf.Spec` can be used to look up types by name or ID and to
inspect the structure of C declarations represented in the object file.

`CollectionSpec.Types` is intended for inspection. Modifying it is not a
supported way to change how a collection is loaded.

Object BTF and kernel BTF serve different purposes. Object BTF describes the
types contained in the eBPF object itself. Kernel BTF describes the target
kernel and is needed by features such as CO-RE to reconcile the object's and the
kernel's types.

## Reading BTF from the running kernel

The `btf` package can also load type information from the running kernel. This
is useful when you need to inspect kernel types directly or when working with
features that depend on kernel BTF.

{{ go_example('DocLoadKernelBTF', title='Inspect BTF types from the running kernel') }}

Use {{ godoc('btf/LoadKernelModuleSpec') }} instead if the type you need lives
in a kernel module rather than `vmlinux`. Kernel module BTF is separate from
`vmlinux` BTF and is loaded as split BTF against the base kernel types.

!!! note ""
    {{ godoc('btf/LoadKernelSpec') }} and {{
    godoc('btf/LoadKernelModuleSpec') }} are convenient for one-off lookups.
    For repeated kernel or module BTF lookups, use {{ godoc('btf/NewCache') }}.

## Lookup methods on `btf.Spec`

Looking closer at {{ godoc('btf/Spec') }}'s API, you'll notice it has a few
methods for looking up types by name:

- {{ godoc('btf/Spec.TypeByName') }}
- {{ godoc('btf/Spec.AnyTypeByName') }}
- {{ godoc('btf/Spec.AnyTypesByName') }}

The '`Any`' prefix means that the type is only queried by name, without it
having to conform to a specific BTF kind, e.g. {{ godoc('btf/Int') }} or {{
godoc('btf/Struct') }}.

Singular '`Type`' means that a lookup must return exactly 1 candidate type in
order to succeed. If multiple candidates with the same name are found, {{
godoc('btf/ErrMultipleMatches') }} is returned.

Conversely, '`Types`' means multiple types with the same name are tolerated so
the caller can manually discern between them.

All lookup methods return an {{ godoc('btf/ErrNotFound') }} if there are no
results.

??? tip "How could an object contain multiple types with the same name?"

    Smaller C programs are typically built into a single `*.o` file, but larger
    projects, like the Linux kernel, are built using multiple [Compilation Units
    (CUs)](https://en.wikipedia.org/wiki/Single_compilation_unit). Each
    compilation unit will have its own copy of common types like `__u64`.

    When CUs are linked together at compile time, their BTF types are
    [deduplicated](https://nakryiko.com/posts/btf-dedup). If subtle differences
    occur (padding, field names, ..), it's possible for multiple instances of
    the same type to be present in the final object, and they will show up in
    BTF multiple times. Be aware that BPF object linking is also a thing (see
    `bpftool gen object`).

## Common operations

The most common BTF operations for {{ proj }} users are:

- Load BTF from an ELF via {{ godoc('LoadCollectionSpec') }} and access it
  through {{ godoc('CollectionSpec.Types') }}
- Load BTF from the running kernel via {{ godoc('btf/LoadKernelSpec') }}
- If your target kernel is too old to support embedded BTF, provide external
  kernel BTF (e.g. from [BTFHub
  Archive](https://github.com/aquasecurity/btfhub-archive)) for CO-RE
  relocations via {{ godoc('ProgramOptions.KernelTypes') }}
- Look up types by name using methods on `btf.Spec`
- Inspect specific type kinds such as `Struct`, `Typedef`, `Int`, and `Var`

The `btf` package also exposes lower-level APIs for building, marshaling, and
loading BTF into the kernel. These are primarily useful for advanced use cases
and library internals and aren't the subject of this page.

## Limitations and portability

BTF availability depends on how both your ELF and your target kernel were built.
Keep the following in mind:

- An ELF built without BTF will not populate `CollectionSpec.Types`.
- Some kernels or distributions may not ship usable kernel BTF.
- Feature availability still depends on the running kernel, even if BTF is present.

When BTF-dependent features fail, the problem is often in the target
environment rather than in your Go code. Verifying that your object was
compiled with `clang -g` and that the target machine provides kernel BTF is a
good first step.
