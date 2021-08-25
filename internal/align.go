package internal

func Align(n, alignment int) int {
	return (int(n) + alignment - 1) / alignment * alignment
}
