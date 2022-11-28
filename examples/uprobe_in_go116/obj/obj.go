package main

import "fmt"

//go:noinline
func Print(msg []byte) {
	fmt.Println(string(msg))
}

func main() {
	msg := []byte("hello world")
	Print(msg)
}
