package ebpf_test

// This code is derived from https://github.com/cloudflare/cloudflare-blog/tree/master/2018-03-ebpf
//
// Copyright (c) 2015-2017 Cloudflare, Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of the Cloudflare, Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/newtools/ebpf"
	"github.com/newtools/ebpf/asm"
)

// ExampleExtractDistance shows how to extract the network distance of
// an IP host.
func Example_extractDistance() {
	var addr = &net.TCPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 53,
	}

	// Call our own socket functions, so that we can attach
	// the eBPF before calling connect. On Go 1.11 you can use
	// Dialer.Control to achieve the same thing.
	fd, err := socket(addr)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	ttls, err := attachBPF(fd)
	if err != nil {
		panic(err)
	}
	defer ttls.Close()

	if err := connect(fd, addr, time.Second); err != nil {
		panic(err)
	}

	minDist, err := minDistance(ttls)
	if err != nil {
		panic(err)
	}

	fmt.Println(addr, "is", minDist, "hops away")

	if err := detachBPF(fd); err != nil {
		panic(err)
	}
}

func attachBPF(fd int) (*ebpf.Map, error) {
	const ETH_P_IPV6 uint16 = 0x86DD
	const SO_ATTACH_BPF = 50

	ttls, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4,
	})
	if err != nil {
		return nil, err
	}

	insns := asm.Instructions{
		// r1 has ctx
		// r0 = ctx[16] (aka protocol)
		asm.LoadMem(asm.R0, asm.R1, 16, asm.Word),

		// Perhaps ipv6
		asm.LoadImm(asm.R2, int64(ETH_P_IPV6), asm.DWord),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.JEq.Reg(asm.R0, asm.R2, "ipv6"),

		// otherwise assume ipv4
		// 8th byte in IPv4 is TTL
		// LDABS requires ctx in R6
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadAbs(-0x100000+8, asm.Byte),
		asm.Ja.Label("store-ttl"),

		// 7th byte in IPv6 is Hop count
		// LDABS requires ctx in R6
		asm.Mov.Reg(asm.R6, asm.R1).Sym("ipv6"),
		asm.LoadAbs(-0x100000+7, asm.Byte),

		// stash the load result into FP[-4]
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word).Sym("store-ttl"),
		// stash the &FP[-4] into r2
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),

		// r1 must point to map
		asm.LoadMapPtr(asm.R1, ttls.FD()),
		asm.MapLookupElement.Call(),

		// load ok? inc. Otherwise? jmp to mapupdate
		asm.JEq.Imm(asm.R0, 0, "update-map"),
		asm.Mov.Imm(asm.R1, 1),
		asm.XAdd(asm.R0, asm.R1, asm.DWord),
		asm.Ja.Label("exit"),

		// MapUpdate
		// r1 has map ptr
		asm.LoadMapPtr(asm.R1, ttls.FD()).Sym("update-map"),
		// r2 has key -> &FP[-4]
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		// r3 has value -> &FP[-16] , aka 1
		asm.StoreImm(asm.RFP, -16, 1, asm.DWord),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		// r4 has flags, 0
		asm.Mov.Imm(asm.R4, 0),
		asm.MapUpdateElement.Call(),

		// set exit code to -1, don't trunc packet
		asm.Mov.Imm(asm.R0, -1).Sym("exit"),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: insns,
	})
	if err != nil {
		ttls.Close()
		return nil, err
	}
	defer prog.Close()

	err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD())
	if err != nil {
		ttls.Close()
		return nil, err
	}

	return ttls, nil
}

func detachBPF(fd int) error {
	const SO_DETACH_BPF = 27
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_DETACH_BPF, 0)
}

func minDistance(ttls *ebpf.Map) (int, error) {
	var (
		entries = ttls.Iterate()
		ttl     uint32
		minDist uint32 = 255
		count   uint64
	)
	for entries.Next(&ttl, &count) {
		var dist uint32
		switch {
		case ttl > 128:
			dist = 255 - ttl
		case ttl > 64:
			dist = 128 - ttl
		case ttl > 32:
			dist = 64 - ttl
		default:
			dist = 32 - ttl
		}
		if minDist > dist {
			minDist = dist
		}
	}
	return int(minDist), entries.Err()
}

func socket(dst *net.TCPAddr) (int, error) {
	var domain int
	if dst.IP.To4() != nil {
		domain = syscall.AF_INET
	} else {
		domain = syscall.AF_INET6
	}

	return syscall.Socket(domain, syscall.SOCK_STREAM, 0)
}

func connect(fd int, dst *net.TCPAddr, timeout time.Duration) error {
	var domain int
	if dst.IP.To4() != nil {
		domain = syscall.AF_INET
	} else {
		domain = syscall.AF_INET6
	}

	var sa syscall.Sockaddr
	if domain == syscall.AF_INET {
		var x [4]byte
		copy(x[:], dst.IP.To4())
		sa = &syscall.SockaddrInet4{Port: dst.Port, Addr: x}
	} else {
		var x [16]byte
		copy(x[:], dst.IP.To16())
		sa = &syscall.SockaddrInet6{Port: dst.Port, Addr: x}
	}

	if ns := timeout.Nanoseconds(); ns > 0 {
		// Set SO_SNDTIMEO
		var tv syscall.Timeval
		tv.Sec = ns / 1000000000
		tv.Usec = (ns - tv.Sec*1000000000) / 1000

		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv); err != nil {
			return err
		}
	}

	// This is blocking.
	return syscall.Connect(fd, sa)
}
