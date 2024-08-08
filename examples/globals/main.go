// This program demonstrates interacting with global variables and constants defined
// in an eBPF program from the userspace. For the example, the program is attached
// to a network interface with XDP (eXpress Data Path).
// The program declares three different types of variables:
//
// 1. `__u64 pkt_count = 0`: 						Initialized to zero -> .bss
// 2. `__u32 another_pkt_count = 0`: 				Initialized to zero -> .bss
// 3. `__u32 random = 1`:							Initialized to != 0 -> .data
// 4. `char var_msg[] = "I can change :)"`:			Initialized to != 0	-> .data
// 5. `const char const_msg[] = "I'm constant :)"`:	Constant variable 	-> .rodata
//
// The userspace program (Go code in this file) prints the contents of all the
// variables, while also changing the value of the `random` and `var_msg` variables.
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Initialize variables that we want to use from userspace
	for _, v := range []*ebpf.Variable{objs.PktCount, objs.Random, objs.ConstMsg, objs.VarMsg} {
		v.Mmap()
	}

	var (
		sb                    strings.Builder
		vPkt                  uint64
		vRandom, newRandomVal uint32
		vMsgConst             []byte = make([]byte, objs.ConstMsg.Size())
		vMsgVar, newMsgVar    []byte = make([]byte, objs.VarMsg.Size()), make([]byte, objs.VarMsg.Size())
	)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err = objs.PktCount.Load(&vPkt); err != nil {
			log.Fatal(err)
		}
		if err = objs.Random.Load(&vRandom); err != nil {
			log.Fatal(err)
		}
		if err = objs.ConstMsg.Load(&vMsgConst); err != nil {
			log.Fatal(err)
		}
		if err = objs.VarMsg.Load(&vMsgVar); err != nil {
			log.Fatal(err)
		}

		newRandomVal = rand.Uint32()
		if err = objs.Random.Store(newRandomVal); err != nil {
			log.Fatal(err)
		}

		copy(newMsgVar, vMsgVar)
		newMsgVar[len(newMsgVar)-2] = (newMsgVar[len(newMsgVar)-2]+1)%2 + 40
		if err = objs.VarMsg.Store(newMsgVar); err != nil {
			log.Fatal(err)
		}
		if err = objs.PktCount.Load(&vPkt); err != nil {
			log.Fatal(err)
		}

		sb.Reset()
		sb.WriteString(fmt.Sprintf("--> PktCount: %20v, ConstMsg: %21s\n", vPkt, vMsgConst))
		sb.WriteString(fmt.Sprintf("--> Random:   %20v, VarMsg:   %21s\n", vRandom, vMsgVar))
		log.Printf("Variables Status:\n%s", sb.String())
	}
}
