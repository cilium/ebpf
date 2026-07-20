# BPF Kernel Functions (kfuncs)

BPF kernel functions, usually called kfuncs, are Linux kernel functions exposed
to eBPF programs. They cover many of the same use cases as BPF helpers, but are
identified through BTF rather than through a stable numeric helper ID.

This difference matters for application authors: helpers are part of the BPF
UAPI, while kfuncs are kernel implementation interfaces. A kfunc's existence,
prototype, verifier rules, and allowed program types can change between kernel
versions. Treat kfuncs as a powerful way to use newer kernel functionality, but
make load-time feature handling part of the design.

!!! note ""
    The Linux kernel documentation describes the kernel-side contract in more
    detail. See [BPF Kernel Functions
    (kfuncs)](https://www.kernel.org/doc/html/latest/bpf/kfuncs.html).

## How {{ proj }} loads kfuncs

{{ proj }} handles kfunc calls during program load. The process is driven by
object BTF and kernel BTF:

1. The eBPF object contains an `extern` function declaration annotated with
   `__ksym`.
2. `clang -g` emits BTF information for that declaration and associates the
   symbol with the virtual `.ksyms` section in the object's BTF.
3. {{ proj }} looks up a function with the same name in the running kernel's
   BTF, including BTF for loaded kernel modules.
4. The loader checks that the object's function prototype is compatible with the
   kernel's prototype.
5. The call instruction is rewritten with the target function's BTF ID. For a
   module kfunc, the instruction also refers to an entry in the module BTF file
   descriptor array passed with the program load request.

No extra Go API is needed for a normal kfunc call. If the program can be loaded
with {{ godoc('LoadCollectionSpec') }}, {{ godoc('NewCollection') }}, or {{
godoc('CollectionSpec.LoadAndAssign') }}, {{ proj }} resolves and rewrites kfunc
calls automatically during program load.

!!! warning ""
    {{ godoc('ProgramOptions.KernelTypes') }} and {{
    godoc('ProgramOptions.ExtraRelocationTargets') }} are used for CO-RE
    relocations. They do not override kfunc resolution. Kfunc calls must resolve
    against the kernel that will actually verify and run the program.

## Declaring kfuncs in eBPF C

Declare the kfunc as an `extern` function and annotate it with `__ksym`. The
declaration should match the kernel's signature. In practice, use `vmlinux.h`
for kernel types and copy the kfunc prototype from the kernel version or kfunc
reference you are targeting.

{{ c_example('kfuncs_required', title='Declare and call a required kfunc') }}

Build eBPF objects with `clang -g` to enable BTF. As with CO-RE, DWARF debug
sections can be stripped afterwards with `llvm-strip -g`. Do not strip the BTF
sections.

## Loading from Go

The Go side looks the same as loading any other collection. Sharing a {{
godoc('btf/Cache') }} is useful when a process loads more than one collection,
because kfunc resolution may need to decode vmlinux and module BTF.

{{ go_example('DocLoadKfuncCollection', title='Load a collection containing kfunc calls') }}

The cache is optional. If `CollectionOptions.Cache` is nil, {{ proj }} creates a
fresh cache for that load.

## Required and optional kfuncs

By default, a kfunc declaration is required. If {{ proj }} can't find it in the
running kernel or in loaded module BTF, loading fails with an error wrapping {{
godoc('ErrNotSupported') }}.

Mark a declaration as `__weak` if the program has a fallback path for kernels
where the kfunc doesn't exist:

{{ c_example('kfuncs_optional', title='Guard optional kfunc calls') }}

For weak kfuncs that aren't present, {{ proj }} rewrites the symbol's address to
zero and makes direct calls to that function fail verification if they remain
reachable. Guard every call with `bpf_ksym_exists()` or another condition the
verifier can prove false when the symbol is missing.

Use `bpf_ksym_exists()` from `<bpf/bpf_helpers.h>` to guard each weak kfunc call.

## Portable kfuncs

Making a kfunc call optional only handles symbol availability. It does not make
the call verifier-compatible across kernels. Portable kfunc usage has two
separate parts:

- The object must be able to load on kernels where the kfunc is unavailable.
- The program must satisfy the verifier rules on kernels where the kfunc is
  available.

Use `__weak` declarations for optional kfuncs and keep fallback paths explicit.
When a choice can be made from user space, combine weak kfuncs with runtime
constants. Set the constant before loading the program so the verifier can prune
the unsupported branch. See [Global Variables](concepts/global-variables.md)
for how to configure constants before load.

Don't assume that a kfunc is available just because the target kernel has BTF.
Availability can depend on kernel version, kernel configuration, whether a
module is loaded, and which BPF program type is being verified.

## Verifier rules

The kernel decides whether a kfunc call is valid. {{ proj }} resolves the call
target, but it does not relax the verifier's rules.

`KF_*` flags are assigned by kernel developers when registering a kfunc set, not
by BPF programs declaring the kfunc.

Common kfunc constraints include:

- **Program type**: kfuncs are registered for specific program types. A kfunc
  that works from TC may be rejected from tracing, or the other way around.
- **Reference tracking**: kfuncs marked `KF_ACQUIRE` return a referenced object.
  The program must release it, usually through a matching `KF_RELEASE` kfunc, or
  transfer it to a kptr map.
- **NULL checks**: kfuncs marked `KF_RET_NULL` may return `NULL`. The verifier
  requires a NULL check before the result can be used as a non-NULL pointer.
- **Trusted arguments**: kfuncs marked `KF_TRUSTED_ARGS` require trusted kernel
  pointers, such as tracepoint arguments or pointers returned from acquire
  kfuncs.
- **Sleepable context**: kfuncs marked `KF_SLEEPABLE` can only be called from
  sleepable BPF programs.

These rules are defined by the kernel's kfunc registration and verifier logic.
If a program fails verification after kfunc resolution succeeds, inspect the
verifier log rather than the Go loader code first.

## Kernel modules

Kfuncs can be provided by kernel modules. {{ proj }} searches both `vmlinux` BTF
and BTF for loaded modules. For module kfuncs to resolve:

- the module must be loaded
- module BTF must be available, typically under `/sys/kernel/btf/<module>`
- the process may need sufficient privilege to inspect BTF handles for loaded
  modules

If a required module kfunc can't be resolved, loading fails. If a weak module
kfunc can't be resolved, {{ proj }} treats it like any other missing weak kfunc:
existence checks evaluate to false, and reachable direct calls fail verification.
