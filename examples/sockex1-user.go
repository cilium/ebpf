package main

import (
	"flag"
	"fmt"
	"syscall"
	"time"

	"github.com/nathanjsweet/ebpf"
	"github.com/nathanjsweet/zsocket/inet"
	"github.com/nathanjsweet/zsocket/nettypes"
)

const SO_ATTACH_BPF = 50

type bKey uint32

func (k bKey) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 4)
	inet.HostByteOrder.PutUint32(ret, uint32(k))
	return ret, nil
}

func (k *bKey) UnmarshalBinary(data []byte) error {
	*k = bKey(inet.HostByteOrder.Uint32(data))
	return nil
}

type bValue uint64

func (k bValue) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 8)
	inet.HostByteOrder.PutUint64(ret, uint64(k))
	return ret, nil
}

func (k *bValue) UnmarshalBinary(data []byte) error {
	*k = bValue(inet.HostByteOrder.Uint64(data))
	return nil
}

func main() {
	fileName := flag.String("file", "", "specific file to debug")
	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()
	coll, err := ebpf.NewBPFCollectionFromFile(*fileName)
	if err != nil {
		fmt.Printf("%s\n", coll.String())
		panic(err)
	}
	sock, err := openRawSock(*index)
	if err != nil {
		panic(err)
	}
	prog := coll.GetProgramByName("bpf_prog1")
	if prog == nil {
		panic(fmt.Errorf("no program named \"bpf_prog1\" found"))
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.GetFd()); err != nil {
		panic(err)
	}
	fmt.Printf("Filtering on eth index: %d\n", *index)
	fmt.Println("Packet stats:")
	bpfMap := coll.GetMapByName("my_map")
	if bpfMap == nil {
		panic(fmt.Errorf("no map named \"my_map\" found"))
	}
	for {
		time.Sleep(time.Second)
		var icmp bValue
		var tcp bValue
		var udp bValue
		ok, err := bpfMap.Get(bKey(nettypes.ICMP), &icmp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "icmp key not found")
		ok, err = bpfMap.Get(bKey(nettypes.TCP), &tcp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "tcp key not found")
		ok, err = bpfMap.Get(bKey(nettypes.UDP), &udp)
		if err != nil {
			panic(err)
		}
		assertTrue(ok, "udp key not found")
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

func assertTrue(b bool, msg string) {
	if !b {
		panic(fmt.Errorf("%s", msg))
	}
}
