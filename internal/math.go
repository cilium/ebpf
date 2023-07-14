package internal

// Align returns 'n' updated to 'alignment' boundary.
func Align[I Integer](n, alignment I) I {
	return (n + alignment - 1) / alignment * alignment
}

// IsPow returns true if n is a power of two.
func IsPow[I Integer](n I) bool {
	return n != 0 && (n&(n-1)) == 0
}

// Integer represents all possible integer types
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}
