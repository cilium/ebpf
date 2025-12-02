//go:build linux

// This program demonstrates using BPF_F_TEST_XDP_LIVE_FRAMES to run an XDP
// program in "live frame mode". In this mode, the kernel sends packets directly
// to the network interface using the XDP program's return value (e.g., XDP_TX).
// This is useful for high-performance packet generation and testing.
//
// Usage: go run . <ifname> <repeat> <batch_size> <src_ip> <dst_ip> <dst_mac>
//
// This example requires Linux kernel version 5.18 or newer.
package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/link"
)

//go:generate go tool bpf2go -tags linux bpf xdp.c -- -I../headers

func main() {
	if len(os.Args) < 7 {
		log.Fatalf("Usage: %s <ifname> <repeat> <batch_size> <src_ip> <dst_ip> <dst_mac>", os.Args[0])
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	repeat, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		log.Fatalf("parsing repeat count %q: %s", os.Args[2], err)
	}

	batchSize, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		log.Fatalf("parsing batch size %q: %s", os.Args[3], err)
	}

	srcIP := net.ParseIP(os.Args[4]).To4()
	if srcIP == nil {
		log.Fatalf("invalid source IP address: %s", os.Args[4])
	}

	dstIP := net.ParseIP(os.Args[5]).To4()
	if dstIP == nil {
		log.Fatalf("invalid destination IP address: %s", os.Args[5])
	}

	dstMAC, err := net.ParseMAC(os.Args[6])
	if err != nil {
		log.Fatalf("invalid destination MAC address %q: %s", os.Args[6], err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach an XDP program to the interface first.
	// This is required for XDP_TX to work in live frame mode.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgPass,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Running XDP program in live frame mode with Repeat: %d, BatchSize: %d", repeat, batchSize)
	log.Printf("Src MAC: %s, Dst MAC: %s", iface.HardwareAddr, dstMAC)
	log.Printf("Src IP: %s, Dst IP: %s", srcIP, dstIP)

	// Build a UDP packet with Ethernet header
	pkt := buildUDPPacket(iface.HardwareAddr, dstMAC, srcIP, dstIP, 12345, 9999, []byte("Hello, XDP!"))

	xdpmd := &sys.XdpMd{
		DataEnd:        uint32(len(pkt)),
		IngressIfindex: uint32(iface.Index),
	}
	ret, err := objs.XdpProgTx.Run(&ebpf.RunOptions{
		Data:      pkt,
		Repeat:    uint32(repeat),
		Flags:     unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context:   xdpmd,
		BatchSize: uint32(batchSize),
	})
	if err != nil {
		log.Fatalf("running XDP program with BPF_F_TEST_XDP_LIVE_FRAMES: %s", err)
	}

	log.Printf("XDP program completed with return value: %d", ret)
}

// buildUDPPacket creates an Ethernet + IPv4 + UDP packet.
func buildUDPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	// Ethernet header (14 bytes)
	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800) // IPv4

	// IPv4 header (20 bytes, no options)
	ipHeaderLen := 20
	udpLen := 8 + len(payload)
	totalLen := ipHeaderLen + udpLen

	ip := make([]byte, ipHeaderLen)
	ip[0] = 0x45                                          // Version (4) + IHL (5)
	ip[1] = 0x00                                          // DSCP + ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen)) // Total length
	binary.BigEndian.PutUint16(ip[4:6], 0x0000)           // Identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)           // Flags (Don't Fragment) + Fragment Offset
	ip[8] = 64                                            // TTL
	ip[9] = 17                                            // Protocol (UDP)
	// ip[10:12] = checksum (calculated below)
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)

	// Calculate IP header checksum
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	// UDP header (8 bytes)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// udp[6:8] = checksum (optional for IPv4, set to 0)

	// Combine all parts
	pkt := make([]byte, 0, 14+totalLen)
	pkt = append(pkt, eth...)
	pkt = append(pkt, ip...)
	pkt = append(pkt, udp...)
	pkt = append(pkt, payload...)

	return pkt
}

// ipChecksum calculates the IP header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
