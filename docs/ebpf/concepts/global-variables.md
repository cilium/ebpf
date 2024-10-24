{{ linux_version("5.2", "For all global variable-related BPF operations,
the kernel needs to understand the BPF_PSEUDO_MAP_VALUE value in ldimm64
instructions. This is needed for direct, lookup-free map access." )}}

Like typical C programs, BPF programs allow the use of global variables. These
variables can be initialized from the BPF C code itself, or they can be modified
by the loading user space application before handing it off to the kernel.

The abstraction {{ proj }} provides to interact with global variables is the
{{ godoc('VariableSpec') }}, found in the {{ godoc('CollectionSpec.Variables') }}
field. This page describes how to declare variables in BPF C and how to interact
with them in Go.

## Runtime Constants

{{ linux_version("5.2", "Read-only maps and the BPF_MAP_FREEZE command are needed
for implementing constant variables.") }}

Global runtime constants are typically used for configuration values that
influence the functionality of a BPF program. Think all sorts of network or
hardware addresses for network filtering, or timeouts for rate limiting. The C
compiler will reject any runtime modifications to these variables in the BPF
program, like a typical const.

Crucially, the BPF verifier will also perform dead code analysis if constants
are used in if statements. If a condition is always true or false, it will
remove unused code paths from the BPF program, reducing verification time and
increasing runtime performance.

This enables many features like portable kfuncs, allowing C code to refer to
kfuncs that may not exist in some kernels, as long as those code paths are
guaranteed not to execute at runtime. Similarly, this can be used to your
advantage to disable code paths that are not needed in certain configurations,
or would result in a verifier error on some kernels or in some contexts.

:ebee-color: Consider the following C BPF program that reads a global constant
and returns it:

{{ c_example('variables_const', title='BPF C program declaring global constant const_u32') }}

??? warning "Why is `const_u32` declared `volatile`?"

    In short: without the `volatile` qualifier, the variable would be optimized
    away and not appear in the BPF object file, leaving us unable to modify it
    from our user space application.

    In this program, the compiler (in)correctly deduces two things about `const_u32`:
    it is never assigned a value, and it doesn't change over the course of the program.
    Implementation details aside, it will now assume that the return value of
    `const_example()` is always 0 and omit the variable from the ELF altogether.

    For BPF programs, it's common practice to declare all global variables that
    need to be accessed from user space as `volatile`, especially non-`const`
    globals. Doing so ensures the compiler reliably allocates them in a data
    section in the ELF.

:simple-go: First, let's take a look at a full Go example that will comprise the
majority of interactions with constants. In the example below, we'll load a BPF
object from disk, pull out a variable, set its value and call the BPF program
once with an empty context. Variations on this pattern will follow later.

{{ go_example('DocVariablesSetConst', title='Go program modifying a const, loading and running the BPF program') }}

1. Any values passed into {{ godoc('VariableSpec.Set') }} must marshal to a
   fixed width. This behaviour is identical to {{ godoc('Map.Put') }} and
   friends. Using untyped integers is not supported since their size is platform
   dependent. We recommend the same approach in BPF C to keep data size
   predictable.
2. A 15-byte context is the minimum the kernel will accept for dry-running a BPF
   program. If your BPF program reads from its context, populating this slice is
   a great way of doing unit testing without setting up a live testing environment.

## Global Variables

Non-const global variables are mutable and can be modified by both the BPF
program and the user space application. They are typically used for keeping
state like metrics, counters, rate limiting, etc.

These variables can also be initialized from user space, much like their `const`
counterparts, and can be both read and written to from the BPF program as well
as the user space application. More on that in a future section.

:ebee-color: The following C BPF program reads a global variable and returns it:

{{ c_example('variables_global', title='BPF C program declaring global variable global_u16') }}

??? warning "Why is `global_u16` declared `volatile`?"

    Similar to `volatile const` in a prior example, `volatile` is used here to
    make compiler output more deterministic. Without it, the compiler may
    choose to optimize away a variable if it's never assigned to, not knowing
    its value is actually provided by user space. The `volatile` qualifier
    doesn't change the variable's semantics.

### Before Loading: Using VariableSpec

For interacting with global variables before loading the BPF program into the
kernel, use the methods on its {{ godoc('VariableSpec') }} found in {{
godoc('CollectionSpec.Variables') }} or injected using {{ godoc('LoadAndAssign')
}}. This ensures the variable is populated before the BPF program has a chance
to execute.

:simple-go: In user space, initialize `global_u16` to 9000:

{{ go_example('DocVariablesSetGlobalU16') }}

Dry-running `global_example()` a few times results in the value increasing on
every invocation:

{{ go_example('DocVariablesSetGlobalRun') }}

Once a CollectionSpec has been loaded into the kernel, further modifications
to a VariableSpec are ineffectual.

### After Loading: Using Variable

After loading the BPF program into the kernel, accessing global variables from
user space can be done through the {{ godoc('Variable') }} abstraction. These
can be injected into an object using {{ godoc('LoadAndAssign') }}, or found in
the {{ godoc('Collection.Variables') }} field.

:simple-go: Building on the previous example, read the incremented variable
using {{ godoc('Variable.Get') }}:

{{ go_example('DocVariablesGetGlobalU16') }}

Modify the Variable at runtime using {{ godoc('Variable.Set') }}.

## Internal/Hidden Global Variables

By default, all global variables described in an ELF's data sections are exposed
through {{ godoc('CollectionSpec.Variables') }}. However, there may be cases
where you don't want user space to interfere with a variable (either on purpose
or by accident) and you want to keep the variable internal to the BPF program.

{{ c_example('variables_hidden', title='BPF C program declaring internal global variable internal_var') }}

The `__hidden` macro is found in Linux' `<bpf/bpf_helpers.h>` as of version 5.13
and is defined as follows:

```c
#define __hidden __attribute__((visibility("hidden")))
```

This will cause the VariableSpec for `hidden_var` to not be included in
the CollectionSpec. 

## Static Global Variables

With the introduction of `bpftool gen object`. BPF received a full-blown static
linker, giving the `static` keyword for declaring objects local to a single .c
file an actual semantic meaning.

{{ proj }} follows the convention set by libbpf to not expose static variables
to user space. In our case, this means that static variables are not included in
the {{ godoc('CollectionSpec.Variables') }} field or emitted in bpf2go-generated
code.

The ELF loader has no way to differentiate function-scoped local variables (also
not exposed) and static variables, since they're both marked with `LOCAL`
linkage in the ELF. If you need to expose a variable to user space, drop the
`static` keyword and declare it in the global scope of your BPF C program.
