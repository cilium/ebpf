//go:build linux

package ebpf_test

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

var program = [...]byte{
	0o177, 0o105, 0o114, 0o106, 0o002, 0o001, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o001, 0o000, 0o367, 0o000, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o340, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o100, 0o000, 0o000, 0o000, 0o000, 0o000, 0o100, 0o000, 0o010, 0o000, 0o001, 0o000,
	0o277, 0o026, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o060, 0o000, 0o000, 0o000, 0o027, 0o000, 0o000, 0o000,
	0o143, 0o012, 0o374, 0o377, 0o000, 0o000, 0o000, 0o000, 0o141, 0o141, 0o004, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o125, 0o001, 0o010, 0o000, 0o004, 0o000, 0o000, 0o000, 0o277, 0o242, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o007, 0o002, 0o000, 0o000, 0o374, 0o377, 0o377, 0o377, 0o030, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o205, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000,
	0o025, 0o000, 0o002, 0o000, 0o000, 0o000, 0o000, 0o000, 0o141, 0o141, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o333, 0o020, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o267, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o225, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o002, 0o000, 0o000, 0o000, 0o004, 0o000, 0o000, 0o000,
	0o010, 0o000, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o002, 0o000, 0o000, 0o000,
	0o004, 0o000, 0o000, 0o000, 0o010, 0o000, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o107, 0o120, 0o114, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o065, 0o000, 0o000, 0o000, 0o000, 0o000, 0o003, 0o000, 0o150, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o034, 0o000, 0o000, 0o000, 0o020, 0o000, 0o006, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o110, 0o000, 0o000, 0o000, 0o020, 0o000, 0o003, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o014, 0o000, 0o000, 0o000, 0o020, 0o000, 0o005, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o023, 0o000, 0o000, 0o000, 0o020, 0o000, 0o005, 0o000, 0o024, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o070, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o001, 0o000, 0o000, 0o000, 0o004, 0o000, 0o000, 0o000, 0o000, 0o056, 0o164, 0o145, 0o170, 0o164, 0o000, 0o155,
	0o141, 0o160, 0o163, 0o000, 0o155, 0o171, 0o137, 0o155, 0o141, 0o160, 0o000, 0o164, 0o145, 0o163, 0o164, 0o137,
	0o155, 0o141, 0o160, 0o000, 0o137, 0o154, 0o151, 0o143, 0o145, 0o156, 0o163, 0o145, 0o000, 0o056, 0o163, 0o164,
	0o162, 0o164, 0o141, 0o142, 0o000, 0o056, 0o163, 0o171, 0o155, 0o164, 0o141, 0o142, 0o000, 0o114, 0o102, 0o102,
	0o060, 0o137, 0o063, 0o000, 0o056, 0o162, 0o145, 0o154, 0o163, 0o157, 0o143, 0o153, 0o145, 0o164, 0o061, 0o000,
	0o142, 0o160, 0o146, 0o137, 0o160, 0o162, 0o157, 0o147, 0o061, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o045, 0o000, 0o000, 0o000, 0o003, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o210, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o122, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o001, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o006, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o100, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o004, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o100, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o006, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o100, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o170, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o010, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o074, 0o000, 0o000, 0o000, 0o011, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o170, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o020, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o007, 0o000, 0o000, 0o000, 0o003, 0o000, 0o000, 0o000,
	0o010, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o020, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o007, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o003, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o270, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o050, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o004, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o035, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o003, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o340, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o004, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o055, 0o000, 0o000, 0o000, 0o002, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o350, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
	0o220, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o001, 0o000, 0o000, 0o000, 0o002, 0o000, 0o000, 0o000,
	0o010, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o030, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
}

// ExampleSocketELF demonstrates how to load an eBPF program from an ELF,
// and attach it to a raw socket.
func Example_socketELF() {
	const SO_ATTACH_BPF = 50

	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program[:]))
	if err != nil {
		panic(err)
	}

	var objs struct {
		Prog  *ebpf.Program `ebpf:"bpf_prog1"`
		Stats *ebpf.Map     `ebpf:"my_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Prog.Close()
	defer objs.Stats.Close()

	sock, err := openRawSock(*index)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, objs.Prog.FD()); err != nil {
		panic(err)
	}

	fmt.Printf("Filtering on eth index: %d\n", *index)
	fmt.Println("Packet stats:")

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
		err := objs.Stats.Lookup(uint32(ICMP), &icmp)
		if err != nil {
			panic(err)
		}
		err = objs.Stats.Lookup(uint32(TCP), &tcp)
		if err != nil {
			panic(err)
		}
		err = objs.Stats.Lookup(uint32(UDP), &udp)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\r\033[m\tICMP: %d TCP: %d UDP: %d", icmp, tcp, udp)
	}
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
