//go:build linux

package examples

import (
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func DocAttachXDP(prog *ebpf.Program) {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		panic(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		panic(err)
	}
	defer l.Close()
}

func DocTCXAnchor(ifaceIndex int, progA, progB *ebpf.Program) {
	first, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex,
		Program:   progA,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		panic(err)
	}
	defer first.Close()

	// Inspect attached programs and obtain the current chain revision.
	res, err := link.QueryPrograms(link.QueryOptions{
		Target: ifaceIndex,
		Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		panic(err)
	}

	// Insert progB before 'first', failing with ESTALE on concurrent edits.
	second, err := link.AttachTCX(link.TCXOptions{
		Interface:        ifaceIndex,
		Program:          progB,
		Attach:           ebpf.AttachTCXIngress,
		Anchor:           link.BeforeLink(first),
		ExpectedRevision: res.Revision,
	})
	if err != nil {
		panic(err)
	}
	defer second.Close()
}

func DocAttachUprobe(prog *ebpf.Program) {
	ex, err := link.OpenExecutable("/bin/bash")
	if err != nil {
		panic(err)
	}

	up, err := ex.Uprobe("readline", prog, nil)
	if err != nil {
		panic(err)
	}
	defer up.Close()
}

func DocAttachIter(prog *ebpf.Program) {
	it, err := link.AttachIter(link.IterOptions{
		Program: prog,
	})
	if err != nil {
		panic(err)
	}
	defer it.Close()

	reader, err := it.Open()
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("read %d bytes\n", len(data))
}
