package main

import "fmt"

func main() {
	fmt.Println(testfunc(1, 2))
}

//go:noinline
func testfunc(a, b int) int {
	return a + b
}
