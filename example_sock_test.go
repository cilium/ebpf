// +build linux

package ebpf_test

import (
	"flag"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/newtools/ebpf"
	"github.com/newtools/ebpf/asm"
	"github.com/newtools/zsocket/inet"
	"github.com/newtools/zsocket/nettypes"
)

type IPHdr struct {
	VersionIHL     uint8
	Tos            uint8
	Length         uint16
	ID             uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          [4]byte
	DestIP         [4]byte
	PayloadLength  int
}

const EthHLen = 14

// ExampleSocket demonstrates how to attach an EBPF program
// to a socket.
func Example_socket() {
	const SO_ATTACH_BPF = 50

	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()
	bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 256,
	})
	if err != nil {
		panic(err)
	}
	ip := IPHdr{}
	mapFd := bpfMap.FD()
	ebpfInss := asm.Instructions{
		// move context to R6 for LoadAbs
		asm.Mov.Reg(asm.R6, asm.R1),
		// get ip protocol
		asm.LoadAbs(int32(EthHLen+unsafe.Offsetof(ip.Protocol)), asm.Byte),
		// set 4 bytes off the frame pointer to be equal to r0
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
		// set 2nd arg (to be given to map fx below) to current FP
		asm.Mov.Reg(asm.R2, asm.RFP),
		// subtract 4 from reg2
		// sub r2, 4
		asm.Sub.Imm(asm.R2, 4),
		// load the map fd into memory, in argument 1 position
		// lddw reg1, (*:from_user_space)(imm)
		asm.LoadImm(asm.R1, int64(mapFd), asm.DWord),
		// call map lookup -> map_lookup_elem(r1, r2)
		// call imm
		asm.MapLookupElement.Call(),
		// exit if reg0 is 0
		// jeq r0, 2, 0
		asm.JEq.Imm(asm.R0, 0, "out"),
		// load int 1 into r1 register
		// mov r1, 1
		asm.Mov.Imm(asm.R1, 1),
		// atomically increment register
		// xaddst r0, r1
		asm.XAdd(asm.R0, asm.R1, asm.DWord),
		// set exit code to 0
		// mov r0, imm
		asm.Mov.Imm(asm.R0, 0).Sym("out"),
		// exit
		asm.Return(),
	}
	bpfProgram, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: ebpfInss,
	})

	if err != nil {
		fmt.Printf("%s\n", ebpfInss)
		panic(err)
	}
	sock, err := openRawSock(*index)
	if err != nil {
		panic(err)
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, bpfProgram.FD()); err != nil {
		panic(err)
	}
	fmt.Printf("Filtering on eth index: %d\n", *index)
	fmt.Println("Packet stats:")
	for {
		time.Sleep(time.Second)
		var icmp uint64
		var tcp uint64
		var udp uint64
		ok, err := bpfMap.Get(uint32(nettypes.ICMP), &icmp)
		if err != nil {
			panic(err)
		}
		if !ok {
			icmp = 0
		}
		ok, err = bpfMap.Get(uint32(nettypes.TCP), &tcp)
		if err != nil {
			panic(err)
		}
		if !ok {
			tcp = 0
		}
		ok, err = bpfMap.Get(uint32(nettypes.UDP), &udp)
		if err != nil {
			panic(err)
		}
		if !ok {
			udp = 0
		}
		fmt.Printf("\r\033[m\tICMP: %d TCP: %d UDP: %d", icmp, tcp, udp)
	}
}

func openRawSock(index int) (int, error) {
	eT := inet.HToNS(nettypes.All[:])
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(eT))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = eT
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}
