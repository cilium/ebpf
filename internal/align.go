package internal

// Align returns 'n' updated to 'alignment' boundary.
func Align[I Integer](n, alignment I) I {
	return (n + alignment - 1) / alignment * alignment
}

// Integer represents all possible integer types
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}
