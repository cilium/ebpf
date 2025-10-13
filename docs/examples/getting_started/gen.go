//go:build linux

// getting_started_gen {
package main

//go:generate go tool bpf2go -tags linux counter counter.c

// }
