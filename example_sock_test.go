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
)

var ipHdr struct {
	VersionIHL     uint8
	Tos            uint8
	Length         uint16
	ID             uint16
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          [4]byte
	DestIP         [4]byte
}

const ethHLen = 14

// ExampleSocket demonstrates how to attach an EBPF program
// to a socket.
func Example_socket() {
	const SO_ATTACH_BPF = 50

	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()

	protoStats, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 256,
	})
	if err != nil {
		panic(err)
	}
	defer protoStats.Close()

	inss := asm.Instructions{
		// move context to R6 for LoadAbs
		asm.Mov.Reg(asm.R6, asm.R1),
		// get ip protocol
		asm.LoadAbs(int32(ethHLen+unsafe.Offsetof(ipHdr.Protocol)), asm.Byte),
		// set 4 bytes off the frame pointer to be equal to r0
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
		// set 2nd arg (to be given to map fx below) to current FP
		asm.Mov.Reg(asm.R2, asm.RFP),
		// subtract 4 from reg2
		// sub r2, 4
		asm.Add.Imm(asm.R2, -4),
		// load the map fd into memory, in argument 1 position
		// lddw reg1, (*:from_user_space)(imm)
		asm.LoadMapPtr(asm.R1, protoStats.FD()),
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

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: inss,
	})
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	sock, err := openRawSock(*index)
	if err != nil {
		panic(err)
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
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
		ok, err := protoStats.Get(uint32(ICMP), &icmp)
		if err != nil {
			panic(err)
		}
		if !ok {
			icmp = 0
		}
		ok, err = protoStats.Get(uint32(TCP), &tcp)
		if err != nil {
			panic(err)
		}
		if !ok {
			tcp = 0
		}
		ok, err = protoStats.Get(uint32(UDP), &udp)
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
	const ETH_P_ALL uint16 = 0x00<<8 | 0x03
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(ETH_P_ALL))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = ETH_P_ALL
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}
