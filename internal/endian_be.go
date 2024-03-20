//go:build armbe || arm64be || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package internal

// ClangEndian is set to either "el" or "eb" depending on the host's endianness.
const ClangEndian = "eb"
