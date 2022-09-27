//go:build linux && !mips && !mipsle && !mips64 && !mips64le

package unix

const (
	SIG_BLOCK   = 0
	SIG_UNBLOCK = 1
)
