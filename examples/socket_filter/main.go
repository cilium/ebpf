package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"

	"github.com/cilium/ebpf/rlimit"
)

// In this example, we only need the compiled ebpf prog FD to obtain the socket. Since this program is
// not only filters for specific connection, the "setsockopt" syscall is directly invoked instead of
// using the link.AttachSocketFilter().

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf socket_filter.c -- -I../headers

const ETH0 = "eth0"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	sockFD, err := attachSocketFilter(ETH0, objs.bpfPrograms.SocketFitler.FD())
	if err != nil {
		log.Fatalf("attach socket filter: %v", err)
	}

	defer syscall.Close(sockFD)
	// It's better to use tools like "gopacket" rather than reading from socket directly.
	// Considering that this is only a demo program, the procedure is simplified.
	processSocket(sockFD)
}

func attachSocketFilter(deviceName string, ebpfProgFD int) (int, error) {
	netInterface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return -1, err
	}

	var sockFD int

	sockFD, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}

	if err = syscall.SetsockoptInt(sockFD, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, ebpfProgFD); err != nil {
		return -1, err
	}

	sll := syscall.SockaddrLinklayer{
		Ifindex:  netInterface.Index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err = syscall.Bind(sockFD, &sll); err != nil {
		return -1, err
	}
	return sockFD, nil
}

// processSocket processes 100 packets from socket.
// Check for each packet if it contains http method.
// If true, print the status line.
func processSocket(sockFD int) {
	fmt.Println("start printing payload for packets with port 80:")

	buf := make([]byte, 65536)
	const MAC_HDR_LEN = 14

	for i := 0; i < 100; i++ {
		n, _, err := syscall.Recvfrom(sockFD, buf, 0)
		if err != nil {
			continue
		}

		layer2 := buf[MAC_HDR_LEN:n]
		// minimum ip header length is 20B
		if len(layer2) < 20 {
			continue
		}

		srcIPBytes := layer2[12:16]
		dstIPBytes := layer2[16:20]

		ipTotalLen := int(layer2[2])<<8 + int(layer2[3])
		ipHdrLen := int(layer2[0]&0xf) << 2
		layer3 := layer2[ipHdrLen:]

		// minimum tcp header length is 20B
		if len(layer3) < 20 {
			continue
		}

		srcPortBytes := layer3[0:2]
		DstPortBytes := layer3[2:4]
		tcpHdrLen := int(layer3[12]&0xf0) >> 2

		payloadLen := ipTotalLen - (tcpHdrLen + ipHdrLen)
		if payloadLen <= 0 {
			continue
		}

		payload := string(layer3[tcpHdrLen:])

		if !httpMethod(payload) {
			continue
		}

		index := strings.Index(payload, "\r\n")
		if index != -1 {
			payload = payload[:index]
		}

		fmt.Printf("    %s:%d -> %s:%d    %s\n",
			ipString(srcIPBytes), portInt(srcPortBytes), ipString(dstIPBytes), portInt(DstPortBytes), payload)
	}

	fmt.Println("packet capture stopped")
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func ipString(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func portInt(port []byte) int {
	return int(port[0])<<8 + int(port[1])
}

func httpMethod(payload string) bool {
	// http requires 8B minimum length
	if len(payload) < 8 {
		return false
	}
	if payload[:3] == "GET" {
		return true
	}
	if payload[:4] == "POST" {
		return true
	}
	if payload[:4] == "HTTP" {
		return true
	}

	// More methods like "PUT" can be added here
	return false
}
