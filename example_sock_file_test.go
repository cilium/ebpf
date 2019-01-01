// +build linux

package ebpf_test

import (
	"flag"
	"fmt"
	"syscall"
	"time"

	"github.com/newtools/ebpf"
)

// ExampleSocketELFFile demonstrates how to load an ELF
// program from a file and attach it to a socket.
func Example_socketELFFile() {
	const SO_ATTACH_BPF = 50

	fileName := flag.String("file", "", "path to sockex1")
	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()
	coll, err := ebpf.LoadCollection(*fileName)
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	sock, err := openRawSock(*index)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	prog := coll.DetachProgram("bpf_prog1")
	if prog == nil {
		panic("no program named bpf_prog1 found")
	}
	defer prog.Close()

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		panic(err)
	}

	fmt.Printf("Filtering on eth index: %d\n", *index)
	fmt.Println("Packet stats:")

	protoStats := coll.DetachMap("my_map")
	if protoStats == nil {
		panic("no map named my_map found")
	}
	defer protoStats.Close()

	for {
		const (
			ICMP = 0x01
			TCP  = 0x06
			UDP  = 0x11
		)

		time.Sleep(time.Second)
		var icmp uint64
		var tcp uint64
		var udp uint64
		ok, err := protoStats.Get(uint32(ICMP), &icmp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "icmp key not found")
		ok, err = protoStats.Get(uint32(TCP), &tcp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "tcp key not found")
		ok, err = protoStats.Get(uint32(UDP), &udp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "udp key not found")
		fmt.Printf("\r\033[m\tICMP: %d TCP: %d UDP: %d", icmp, tcp, udp)
	}
}
