// Freestanding executable used as a uprobe target by tests, so they don't
// depend on binaries present in the test environment.

// Raw syscalls to avoid depending on a libc, which would significantly inflate
// the output binary size when statically linking, as well as complicate the
// build process.
static __attribute__((noreturn)) void sys_exit(int code) {
#if defined(__x86_64__)
	__asm__ volatile("syscall" : : "a"(60), "D"(code) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
	register long x8 __asm__("x8") = 93;
	register long x0 __asm__("x0") = code;
	__asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
#else
#error "unsupported architecture"
#endif
	__builtin_unreachable();
}

// Returns to its caller, so a uretprobe on it fires.
__attribute__((noinline)) int uprobe_returns(int x) {
	return x;
}

// Never returns, so a uretprobe on it doesn't fire.
__attribute__((noinline, noreturn)) void uprobe_exits(int code) {
	sys_exit(code);
}

void _start(void) {
	uprobe_exits(uprobe_returns(0));
}
